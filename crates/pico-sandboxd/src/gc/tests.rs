use super::*;
use crate::ledger::{BeginOperation, BeginOperationRequest};
use crate::supervisor::{
    CommandContext, OperationKind, OperationOutcome, OutcomeReason, OutcomeStatus,
};
use pico_core::{FencingToken, ResourceReceipt, SandboxState};

#[test]
fn resource_class_roundtrip_all_variants() {
    let classes = [
        ResourceClass::Workspace,
        ResourceClass::Cgroup,
        ResourceClass::Cpu,
        ResourceClass::Process,
        ResourceClass::Mount,
        ResourceClass::NetworkDevice,
        ResourceClass::Uds,
        ResourceClass::Vsock,
        ResourceClass::TempFile,
        ResourceClass::Other,
    ];
    for class in classes {
        let serialized = class.as_str();
        let deserialized = ResourceClass::parse(serialized);
        assert_eq!(deserialized, Some(class));
    }
}

#[test]
fn gc_action_roundtrip_all_variants() {
    let actions = [
        GcAction::Removed,
        GcAction::RequiresReview,
        GcAction::Confirmed,
        GcAction::AlreadyAbsent,
    ];
    for action in actions {
        let serialized = action.as_str();
        let deserialized = GcAction::parse(serialized);
        assert_eq!(deserialized, Some(action));
    }
}

#[test]
fn has_unsafe_findings_detects_cleanup_failures() {
    let stats = GcStats::default();
    assert!(!has_unsafe_findings(&stats));
    let stats = GcStats {
        cleanup_failed: 1,
        ..Default::default()
    };
    assert!(has_unsafe_findings(&stats));
    // review_required alone does not make it unsafe
    let stats = GcStats {
        review_required: 5,
        ..Default::default()
    };
    assert!(!has_unsafe_findings(&stats));
}
#[test]
fn gc_stats_default_is_zero() {
    let stats = GcStats::default();
    assert_eq!(stats.receipts_scanned, 0);
    assert_eq!(stats.removed, 0);
    assert_eq!(stats.review_required, 0);
    assert_eq!(stats.cleanup_failed, 0);
    assert_eq!(stats.scan_duration_ms, 0);
}

#[tokio::test]
async fn scan_skips_autoremoval_for_live_sandboxes() {
    let (gc, _ledger, _root, sbx) = seeded_receipt(SandboxState::Running).await;

    let stats = gc.scan_pass().await.unwrap();

    assert_eq!(stats.removed, 0);
    assert_eq!(stats.review_required, 0);
    assert!(gc.workspace_root.join(&sbx).is_dir());
}

#[tokio::test]
async fn scan_removes_workspace_receipt_for_destroyed_sandbox() {
    let (gc, ledger, _root, sbx) = seeded_receipt(SandboxState::Running).await;
    transition_to_destroyed(&ledger, &gc, &sbx).await;

    let stats = gc.scan_pass().await.unwrap();

    assert_eq!(stats.removed, 1);
    assert_eq!(stats.review_required, 0);
    assert!(!gc.workspace_root.join(&sbx).exists());
    assert!(ledger.list_gc_scan_rows().await.unwrap().is_empty());
}

#[tokio::test]
async fn scan_removes_parseable_cpu_receipt_for_destroyed_sandbox() {
    let (gc, ledger, _root, sbx) = seeded_cpu_receipt(
        SandboxState::Running,
        Some(r#"{"version":1,"tenant_id":"tnt_1","cpus":[0]}"#),
    )
    .await;
    transition_to_destroyed(&ledger, &gc, &sbx).await;

    let stats = gc.scan_pass().await.unwrap();

    assert_eq!(stats.removed, 1);
    assert_eq!(stats.review_required, 0);
    assert!(ledger.list_gc_scan_rows().await.unwrap().is_empty());
}

#[tokio::test]
async fn scan_keeps_unparsable_cpu_receipt_for_review() {
    let (gc, ledger, _root, sbx) =
        seeded_cpu_receipt(SandboxState::Running, Some("not-json")).await;
    transition_to_destroyed(&ledger, &gc, &sbx).await;

    let stats = gc.scan_pass().await.unwrap();

    assert_eq!(stats.removed, 0);
    assert_eq!(stats.review_required, 1);
    let remaining = ledger.list_gc_scan_rows().await.unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].resource_name, format!("cpu/{sbx}"));
}

#[tokio::test]
async fn scan_releases_already_absent_workspace_without_review() {
    let (gc, ledger, _root, sbx) = seeded_receipt(SandboxState::Running).await;
    // Destroy leaves a present receipt but the directory is already gone
    // (for example a concurrent cleanup). Converge without operator action.
    std::fs::remove_dir_all(gc.workspace_root.join(&sbx)).unwrap();
    transition_to_destroyed(&ledger, &gc, &sbx).await;

    let stats = gc.scan_pass().await.unwrap();

    assert_eq!(stats.removed, 1);
    assert_eq!(stats.review_required, 0);
    assert!(ledger.list_gc_scan_rows().await.unwrap().is_empty());
}

#[tokio::test]
async fn scan_keeps_non_directory_workspace_for_review() {
    let (gc, ledger, root, sbx) = seeded_receipt(SandboxState::Running).await;
    let path = root.path().join(&sbx);
    std::fs::remove_dir_all(&path).unwrap();
    std::fs::write(&path, b"not-a-directory").unwrap();
    transition_to_destroyed(&ledger, &gc, &sbx).await;

    let stats = gc.scan_pass().await.unwrap();

    assert_eq!(stats.removed, 0);
    assert_eq!(stats.review_required, 1);
    let remaining = ledger.list_gc_scan_rows().await.unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].resource_name, format!("workspace/{sbx}"));
    assert!(path.is_file());
}

#[tokio::test]
async fn scan_keeps_unknown_resource_class_for_review() {
    let root = TempDirGuard::new();
    let sbx = "sbx_gc_unknown".to_string();
    let ledger = seed_ledger(
        &sbx,
        SandboxState::Running,
        &[ResourceReceipt {
            class: "network_device".into(),
            name: format!("tap/{sbx}"),
            external_id: None,
        }],
    )
    .await;
    let host = crate::resources::HostResourceManager::new(
        crate::resources::HostResourceConfig::new(root.path().to_path_buf()),
    );
    let gc = GarbageCollector::new(ledger.clone(), host, DEFAULT_GC_INTERVAL);
    transition_to_destroyed(&ledger, &gc, &sbx).await;

    let stats = gc.scan_pass().await.unwrap();

    assert_eq!(stats.removed, 0);
    assert_eq!(stats.review_required, 1);
    let remaining = ledger.list_gc_scan_rows().await.unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].resource_class, "network_device");
}

/// Seeds the ledger with one workspace receipt for a sandbox in the given
/// observed state, plus a real workspace directory on disk.
async fn seeded_receipt(state: SandboxState) -> (GarbageCollector, Ledger, TempDirGuard, String) {
    let root = TempDirGuard::new();
    let sbx = "sbx_gc_live".to_string();
    let ledger = seed_ledger(
        &sbx,
        state,
        &[ResourceReceipt {
            class: "workspace".into(),
            name: format!("workspace/{sbx}"),
            external_id: None,
        }],
    )
    .await;
    std::fs::create_dir_all(root.path().join(&sbx)).unwrap();
    let host = crate::resources::HostResourceManager::new(
        crate::resources::HostResourceConfig::new(root.path().to_path_buf()),
    );
    let gc = GarbageCollector::new(ledger.clone(), host, DEFAULT_GC_INTERVAL);
    (gc, ledger, root, sbx)
}

/// Seeds the ledger with one cpu receipt carrying the given serialized
/// allocation payload for a sandbox in the given observed state.
async fn seeded_cpu_receipt(
    state: SandboxState,
    external_id: Option<&str>,
) -> (GarbageCollector, Ledger, TempDirGuard, String) {
    let root = TempDirGuard::new();
    let sbx = "sbx_gc_cpu".to_string();
    let ledger = seed_ledger(
        &sbx,
        state,
        &[ResourceReceipt {
            class: "cpu".into(),
            name: format!("cpu/{sbx}"),
            external_id: external_id.map(str::to_string),
        }],
    )
    .await;
    let host = crate::resources::HostResourceManager::new(
        crate::resources::HostResourceConfig::new(root.path().to_path_buf()),
    );
    let gc = GarbageCollector::new(ledger.clone(), host, DEFAULT_GC_INTERVAL);
    (gc, ledger, root, sbx)
}

/// Begins and completes a prepare operation in the ledger, attaching the given
/// resource receipts and leaving the sandbox in the given observed state.
async fn seed_ledger(sbx: &str, state: SandboxState, receipts: &[ResourceReceipt]) -> Ledger {
    use pico_core::{BackendCapabilities, BackendMetadata, OperationId, RuntimeType, SandboxId};

    let ledger = Ledger::in_memory();
    ledger.initialize().await.unwrap();
    let metadata = BackendMetadata {
        runtime: RuntimeType::Qemu,
        version: "test".into(),
        capabilities: BackendCapabilities::from([]),
    };
    let sandbox_id = SandboxId::from_string(sbx);
    let context = CommandContext::with_timeout(
        sandbox_id.clone(),
        OperationId::generate(),
        FencingToken::default(),
        1,
        Duration::from_secs(30),
    );
    let begun = ledger
        .begin_operation(BeginOperationRequest {
            context: &context,
            kind: OperationKind::Prepare,
            metadata: &metadata,
            state: SandboxState::Preparing,
            host_boot_id: "test",
        })
        .await
        .unwrap();
    assert!(matches!(begun, BeginOperation::Execute));
    let outcome = OperationOutcome {
        operation_id: context.operation_id.clone(),
        sandbox_id: sandbox_id.clone(),
        kind: OperationKind::Prepare,
        status: OutcomeStatus::Succeeded,
        reason: OutcomeReason::Completed,
        non_ready_reason: None,
        message: None,
        completed_at: pico_core::now_iso(),
    };
    ledger
        .complete_operation(&outcome, state, receipts)
        .await
        .unwrap();
    ledger
}

/// Transitions the seeded sandbox to Destroyed so GC owns cleanup again.
async fn transition_to_destroyed(ledger: &Ledger, _gc: &GarbageCollector, sbx: &str) {
    use pico_core::{BackendCapabilities, BackendMetadata, OperationId, RuntimeType};

    let metadata = BackendMetadata {
        runtime: RuntimeType::Qemu,
        version: "test".into(),
        capabilities: BackendCapabilities::from([]),
    };
    let sandbox_id = pico_core::SandboxId::from_string(sbx);
    let context = CommandContext::with_timeout(
        sandbox_id.clone(),
        OperationId::generate(),
        FencingToken::default(),
        1,
        Duration::from_secs(30),
    );
    ledger
        .begin_operation(BeginOperationRequest {
            context: &context,
            kind: OperationKind::Destroy,
            metadata: &metadata,
            state: SandboxState::Destroying,
            host_boot_id: "test",
        })
        .await
        .unwrap();
    let outcome = OperationOutcome {
        operation_id: context.operation_id.clone(),
        sandbox_id,
        kind: OperationKind::Destroy,
        status: OutcomeStatus::Succeeded,
        reason: OutcomeReason::Completed,
        non_ready_reason: None,
        message: None,
        completed_at: pico_core::now_iso(),
    };
    ledger
        .complete_operation(&outcome, SandboxState::Destroyed, &[])
        .await
        .unwrap();
}

struct TempDirGuard {
    path: PathBuf,
}

impl TempDirGuard {
    fn new() -> Self {
        Self {
            path: std::env::temp_dir().join(pico_core::new_ulid("pico_gc_test")),
        }
    }

    fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

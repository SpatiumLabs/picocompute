//! Integration tests for: Keep runtime credentials out of checkpoints.
//!
//! Validates:
//! - Credential exclusion from snapshot metadata and blobs
//! - Credential refresh policy after restore
//! - Fork credential inheritance policy
//! - Negative test with intentionally misplaced credential fixture
//! - Audit event emission for credential refresh and denial

use async_trait::async_trait;
use parking_lot::Mutex;
use pico_core::identity::{OperationId, SnapshotId};
use pico_core::{
    AuditEvent, AuditEventDetails, AuditEventKind, AuditOutcome, SandboxId, TenantId,
    event_bus::{
        CredentialIssuanceParams, InMemoryAuditSink, emit_credential_issuance, redact_event,
    },
    mount::{MountClass, MountContract, MountEntry, PathLifecycle},
    snapshot::{
        self, BlobInfo, BlobLocator, CompatibilityRecord, CredentialExclusionResult,
        CredentialRefreshOutcome, CredentialSnapshotPolicy, FilesystemRef, ForkCredentialPolicy,
        LineageType, RestoreOrchestrator, SnapshotError, SnapshotMetadata, SnapshotProfile,
        SnapshotPurpose, SnapshotState,
        repository::SnapshotRepository,
        shape::{BackendRecord, CpuShape, DeviceModel, MemoryShape},
    },
};
use std::sync::Arc;

// Mount contract credential exclusion

#[test]
fn production_mount_contract_excludes_secrets_from_snapshot() {
    let contract = MountContract {
        version: "1".into(),
        mounts: vec![
            MountEntry {
                path: "/workspace".into(),
                class: MountClass::Workspace,
                writable: true,
                lifecycle: PathLifecycle::Persistent,
            },
            MountEntry {
                path: "/run/pico/secrets".into(),
                class: MountClass::Secret,
                writable: false,
                lifecycle: PathLifecycle::Ephemeral,
            },
        ],
    };

    let excluded = contract.snapshot_excluded_classes();
    assert!(
        excluded.contains(&"secret".to_string()),
        "secret class must be excluded from snapshots"
    );
}

#[test]
fn mount_contract_enforces_secret_is_ephemeral() {
    let contract = MountContract {
        version: "1".into(),
        mounts: vec![MountEntry {
            path: "/run/pico/secrets".into(),
            class: MountClass::Secret,
            writable: false,
            lifecycle: PathLifecycle::Ephemeral,
        }],
    };
    assert!(
        contract.is_valid().is_ok(),
        "valid secret mount should pass validation"
    );
}

#[test]
fn mount_contract_rejects_persistent_secret_mount() {
    let contract = MountContract {
        version: "1".into(),
        mounts: vec![MountEntry {
            path: "/run/pico/secrets".into(),
            class: MountClass::Secret,
            writable: false,
            lifecycle: PathLifecycle::Persistent,
        }],
    };
    assert!(
        contract.is_valid().is_err(),
        "persistent secret mount should be rejected"
    );
}

#[test]
fn mount_contract_rejects_writable_secret_mount() {
    let contract = MountContract {
        version: "1".into(),
        mounts: vec![MountEntry {
            path: "/run/pico/secrets".into(),
            class: MountClass::Secret,
            writable: true,
            lifecycle: PathLifecycle::Ephemeral,
        }],
    };
    assert!(
        contract.is_valid().is_err(),
        "writable secret mount should be rejected"
    );
}

// Snapshot metadata ensures credential exclusion

#[test]
fn snapshot_metadata_stores_excluded_mount_classes() {
    let mut meta = SnapshotMetadata::new(
        SnapshotId::generate(),
        TenantId::from_string("tnt_test"),
        SandboxId::generate(),
        None,
        LineageType::Root,
        SnapshotPurpose::Session,
        SnapshotProfile::Filesystem,
        OperationId::generate(),
        "img_test".into(),
        BackendRecord {
            backend_type: "firecracker".into(),
            backend_version: "1.10.0".into(),
            protocol_version: "2.0".into(),
            guest_agent_version: Some("0.5.0".into()),
        },
        CpuShape::new("x86_64"),
        MemoryShape {
            memory_mb: 2048,
            vcpus: 2,
        },
        DeviceModel::new("q35"),
    );

    meta.excluded_mounts = vec!["secret".into()];
    assert!(meta.excluded_mounts.contains(&"secret".to_string()));
}

#[test]
fn snapshot_metadata_validates_credential_exclusion() {
    let mut meta = SnapshotMetadata::new(
        SnapshotId::generate(),
        TenantId::from_string("tnt_test"),
        SandboxId::generate(),
        None,
        LineageType::Root,
        SnapshotPurpose::Session,
        SnapshotProfile::Filesystem,
        OperationId::generate(),
        "img_test".into(),
        BackendRecord {
            backend_type: "firecracker".into(),
            backend_version: "1.10.0".into(),
            protocol_version: "2.0".into(),
            guest_agent_version: Some("0.5.0".into()),
        },
        CpuShape::new("x86_64"),
        MemoryShape {
            memory_mb: 2048,
            vcpus: 2,
        },
        DeviceModel::new("q35"),
    );

    meta.credential_policy = Some(CredentialSnapshotPolicy::production());
    meta.excluded_mounts = vec!["secret".into(), "runtime_tmp".into()];

    let result = meta.validate_credential_exclusion();
    assert!(
        result.is_ok(),
        "credential exclusion validation should pass"
    );
}

#[test]
fn snapshot_metadata_detects_missing_credential_policy() {
    let mut meta = SnapshotMetadata::new(
        SnapshotId::generate(),
        TenantId::from_string("tnt_test"),
        SandboxId::generate(),
        None,
        LineageType::Root,
        SnapshotPurpose::Session,
        SnapshotProfile::Filesystem,
        OperationId::generate(),
        "img_test".into(),
        BackendRecord {
            backend_type: "firecracker".into(),
            backend_version: "1.10.0".into(),
            protocol_version: "2.0".into(),
            guest_agent_version: Some("0.5.0".into()),
        },
        CpuShape::new("x86_64"),
        MemoryShape {
            memory_mb: 2048,
            vcpus: 2,
        },
        DeviceModel::new("q35"),
    );

    meta.excluded_mounts = vec!["secret".into()];
    // credential_policy is None

    let result = meta.validate_credential_exclusion();
    assert!(
        matches!(
            result,
            Err(SnapshotError::CredentialExclusionInvalid { .. })
        ),
        "should error when credential policy is missing"
    );
}

#[test]
fn compatibility_record_includes_credential_policy() {
    let mut meta = SnapshotMetadata::new(
        SnapshotId::generate(),
        TenantId::from_string("tnt_test"),
        SandboxId::generate(),
        None,
        LineageType::Root,
        SnapshotPurpose::Session,
        SnapshotProfile::Filesystem,
        OperationId::generate(),
        "img_test".into(),
        BackendRecord {
            backend_type: "firecracker".into(),
            backend_version: "1.10.0".into(),
            protocol_version: "2.0".into(),
            guest_agent_version: Some("0.5.0".into()),
        },
        CpuShape::new("x86_64"),
        MemoryShape {
            memory_mb: 2048,
            vcpus: 2,
        },
        DeviceModel::new("q35"),
    );

    meta.credential_policy = Some(CredentialSnapshotPolicy::production());
    meta.excluded_mounts = vec!["secret".into()];

    let compat: CompatibilityRecord = meta.to_compatibility_record();
    assert!(compat.credential_policy.is_some());
    let policy = compat.credential_policy.unwrap();
    assert!(policy.exclude_from_snapshot);
    assert!(policy.refresh_after_restore);
    assert_eq!(policy.fork_credential_policy, ForkCredentialPolicy::None);
}

// Credential snapshot policy

#[test]
fn credential_snapshot_policy_production_defaults() {
    let policy = CredentialSnapshotPolicy::production();
    assert!(policy.exclude_from_snapshot);
    assert!(policy.refresh_after_restore);
    assert_eq!(policy.fork_credential_policy, ForkCredentialPolicy::None);
    assert!(policy.require_lease_for_refresh);
}

#[test]
fn credential_snapshot_policy_allows_specific_types() {
    let policy = CredentialSnapshotPolicy {
        allowed_credential_types: vec!["aws".into(), "gcp".into()],
        ..Default::default()
    };
    assert!(policy.allows_credential_type("aws"));
    assert!(policy.allows_credential_type("gcp"));
    assert!(!policy.allows_credential_type("azure"));
}

#[test]
fn credential_snapshot_policy_serde_roundtrip() {
    let policy = CredentialSnapshotPolicy {
        exclude_from_snapshot: true,
        refresh_after_restore: true,
        fork_credential_policy: ForkCredentialPolicy::None,
        allowed_credential_types: vec!["aws".into()],
        require_lease_for_refresh: true,
    };
    let json = serde_json::to_string(&policy).unwrap();
    let back: CredentialSnapshotPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, back);
}

// Fork credential policy

#[test]
fn fork_credential_policy_default_is_none() {
    assert_eq!(ForkCredentialPolicy::None.as_str(), "none");
}

#[test]
fn fork_credential_policy_inherit_all() {
    assert_eq!(ForkCredentialPolicy::InheritAll.as_str(), "inherit_all");
}

// Credential refresh outcome

#[test]
fn credential_refresh_outcome_refreshed() {
    let outcome = CredentialRefreshOutcome::Refreshed {
        credential_count: 5,
        lease_id: Some("lse_test".into()),
    };
    assert!(outcome.is_refreshed());
    assert!(!outcome.is_terminal_failure());
}

#[test]
fn credential_refresh_outcome_denied() {
    let outcome = CredentialRefreshOutcome::Denied {
        reason: "no valid lease".into(),
    };
    assert!(!outcome.is_refreshed());
    assert!(outcome.is_terminal_failure());
}

// Credential exclusion result

#[test]
fn credential_exclusion_result_success() {
    let result = CredentialExclusionResult::success(vec!["secret".into()]);
    assert!(result.is_valid());
    assert!(result.enforced);
    assert!(result.secret_class_excluded);
}

#[test]
fn credential_exclusion_result_failure() {
    let result = CredentialExclusionResult::failure(vec!["secret class missing".into()]);
    assert!(!result.is_valid());
}

// Audit events for credential issuance and denial

fn make_audit_sink() -> Arc<InMemoryAuditSink> {
    Arc::new(InMemoryAuditSink::new())
}

#[test]
fn emit_credential_issuance_produces_audit_event() {
    let sink = make_audit_sink();
    let hlc = Arc::new(pico_core::identity::Hlc::new());
    let sandbox_id = SandboxId::from_string("sbx_audit_cred");
    let tenant_id = TenantId::from_string("tnt_audit_cred");

    emit_credential_issuance(
        sink.as_ref(),
        &hlc,
        CredentialIssuanceParams {
            action: "issue".into(),
            outcome: AuditOutcome::Issued.into(),
            reason: Some("credential refreshed on restore".into()),
            credential_type: "aws".into(),
            lease_id: Some("lse_cred_001".into()),
            sandbox_id: sandbox_id.clone(),
            tenant_id: tenant_id.clone(),
        },
    );

    let events: Vec<AuditEvent> = sink.events();
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event.kind, AuditEventKind::CredentialIssuance);
    assert_eq!(
        event.sandbox_id.as_ref().unwrap().as_str(),
        "sbx_audit_cred"
    );
    assert_eq!(event.tenant_id.as_ref().unwrap().as_str(), "tnt_audit_cred");
    assert_eq!(event.outcome.as_deref(), Some("issued"));
}

#[test]
fn emit_credential_denial_produces_audit_event() {
    let sink = make_audit_sink();
    let hlc = Arc::new(pico_core::identity::Hlc::new());
    let sandbox_id = SandboxId::from_string("sbx_deny_cred");
    let tenant_id = TenantId::from_string("tnt_deny_cred");

    emit_credential_issuance(
        sink.as_ref(),
        &hlc,
        CredentialIssuanceParams {
            action: "deny".into(),
            outcome: AuditOutcome::Denied.into(),
            reason: Some("no valid lease".into()),
            credential_type: "gcp".into(),
            lease_id: None,
            sandbox_id: sandbox_id.clone(),
            tenant_id: tenant_id.clone(),
        },
    );

    let events: Vec<AuditEvent> = sink.events();
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event.kind, AuditEventKind::CredentialIssuance);
    assert_eq!(event.outcome.as_deref(), Some("denied"));
}

#[test]
fn audit_event_credential_fields_are_preserved_after_redaction() {
    let sink = make_audit_sink();
    let hlc = Arc::new(pico_core::identity::Hlc::new());

    emit_credential_issuance(
        sink.as_ref(),
        &hlc,
        CredentialIssuanceParams {
            action: "refresh".into(),
            outcome: AuditOutcome::Success.into(),
            reason: Some("credentials refreshed on resume".into()),
            credential_type: "short_lived_token".into(),
            lease_id: Some("lse_safe_001".into()),
            sandbox_id: SandboxId::from_string("sbx_safe"),
            tenant_id: TenantId::from_string("tnt_safe"),
        },
    );

    let mut events: Vec<AuditEvent> = sink.events();
    assert_eq!(events.len(), 1);

    redact_event(&mut events[0]);

    let event = &events[0];
    match event.details.as_ref().unwrap() {
        AuditEventDetails::CredentialIssuance {
            action,
            outcome,
            reason,
            credential_type,
            lease_id,
        } => {
            assert_eq!(action, "refresh");
            assert_eq!(outcome, "success");
            // Safe reason should be preserved
            assert_eq!(reason.as_deref(), Some("credentials refreshed on resume"));
            assert_eq!(credential_type, "short_lived_token");
            assert_eq!(lease_id.as_deref(), Some("lse_safe_001"));
        }
        _ => panic!("expected CredentialIssuance details"),
    }
}

// Negative test: intentionally misplaced credential fixture

#[test]
fn detect_credential_mount_in_filesystem_refs() {
    let mut meta = SnapshotMetadata::new(
        SnapshotId::generate(),
        TenantId::from_string("tnt_neg"),
        SandboxId::generate(),
        None,
        LineageType::Root,
        SnapshotPurpose::Session,
        SnapshotProfile::Filesystem,
        OperationId::generate(),
        "img_test".into(),
        BackendRecord {
            backend_type: "firecracker".into(),
            backend_version: "1.10.0".into(),
            protocol_version: "2.0".into(),
            guest_agent_version: Some("0.5.0".into()),
        },
        CpuShape::new("x86_64"),
        MemoryShape {
            memory_mb: 2048,
            vcpus: 2,
        },
        DeviceModel::new("q35"),
    );

    meta.credential_policy = Some(CredentialSnapshotPolicy::production());
    // "secret" is in excluded_mounts, but a filesystem ref has the credential mount point
    meta.excluded_mounts = vec!["secret".into()];

    // Intentionally misplaced credential fixture
    meta.filesystem_refs.push(FilesystemRef {
        blob_ref: "leaked-secrets.ext4".into(),
        mount_point: "/run/pico/secrets".into(),
        fs_type: "ext4".into(),
        digest: Some("blake3:bad123".into()),
        is_root: false,
    });

    let result = meta.validate_credential_exclusion();
    assert!(
        matches!(
            result,
            Err(SnapshotError::CredentialMaterialDetected { .. })
        ),
        "should detect credential material in filesystem refs: {:?}",
        result
    );
}

// Restore orchestrator credential scan

struct TestRepo {
    snapshots: Mutex<Vec<SnapshotMetadata>>,
}

impl TestRepo {
    fn new() -> Self {
        Self {
            snapshots: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl SnapshotRepository for TestRepo {
    async fn get_snapshot(
        &self,
        id: &SnapshotId,
    ) -> snapshot::error::SnapshotResult<SnapshotMetadata> {
        self.snapshots
            .lock()
            .iter()
            .find(|m| m.id == *id)
            .cloned()
            .ok_or_else(|| SnapshotError::SnapshotNotFound { id: id.to_string() })
    }

    async fn store_snapshot(
        &self,
        metadata: &SnapshotMetadata,
    ) -> snapshot::error::SnapshotResult<()> {
        self.snapshots.lock().push(metadata.clone());
        Ok(())
    }

    async fn update_snapshot(
        &self,
        metadata: &SnapshotMetadata,
        _version: u64,
    ) -> snapshot::error::SnapshotResult<()> {
        let mut guard = self.snapshots.lock();
        if let Some(existing) = guard.iter_mut().find(|m| m.id == metadata.id) {
            *existing = metadata.clone();
        }
        Ok(())
    }

    async fn list_snapshots(
        &self,
        _tenant_id: &TenantId,
        _purpose: Option<SnapshotPurpose>,
        _state: Option<SnapshotState>,
        _limit: usize,
        _cursor: Option<String>,
    ) -> snapshot::error::SnapshotResult<snapshot::repository::SnapshotListPage> {
        Ok(snapshot::repository::SnapshotListPage {
            snapshots: self.snapshots.lock().clone(),
            next_cursor: None,
        })
    }

    async fn delete_snapshot(&self, id: &SnapshotId) -> snapshot::error::SnapshotResult<()> {
        self.snapshots.lock().retain(|m| m.id != *id);
        Ok(())
    }
}

struct TestBlobLocator {
    blobs: Mutex<Vec<BlobInfo>>,
}

impl TestBlobLocator {
    fn new() -> Self {
        Self {
            blobs: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl BlobLocator for TestBlobLocator {
    async fn locate_blob(&self, blob_ref: &str) -> snapshot::error::SnapshotResult<BlobInfo> {
        self.blobs
            .lock()
            .iter()
            .find(|b| b.blob_ref == blob_ref)
            .cloned()
            .ok_or_else(|| SnapshotError::BlobMissing {
                blob_ref: blob_ref.to_string(),
            })
    }
}

#[test]
fn restore_orchestrator_scans_credential_material() {
    let repo = Arc::new(TestRepo::new());
    let blobs = Arc::new(TestBlobLocator::new());
    let orchestrator = RestoreOrchestrator::new(repo, blobs);

    let mut meta = SnapshotMetadata::new(
        SnapshotId::generate(),
        TenantId::from_string("tnt_test"),
        SandboxId::generate(),
        None,
        LineageType::Root,
        SnapshotPurpose::Session,
        SnapshotProfile::Filesystem,
        OperationId::generate(),
        "img_test".into(),
        BackendRecord {
            backend_type: "firecracker".into(),
            backend_version: "1.10.0".into(),
            protocol_version: "2.0".into(),
            guest_agent_version: Some("0.5.0".into()),
        },
        CpuShape::new("x86_64"),
        MemoryShape {
            memory_mb: 2048,
            vcpus: 2,
        },
        DeviceModel::new("q35"),
    );

    meta.credential_policy = Some(CredentialSnapshotPolicy::production());
    meta.excluded_mounts = vec!["secret".into(), "runtime_tmp".into()];

    // Clean snapshot
    let result = orchestrator.scan_for_credential_material(&meta);
    assert!(result.is_ok(), "clean snapshot should pass scan");
}

#[test]
fn restore_orchestrator_scans_credential_material_with_contamination() {
    let repo = Arc::new(TestRepo::new());
    let blobs = Arc::new(TestBlobLocator::new());
    let orchestrator = RestoreOrchestrator::new(repo, blobs);

    let mut meta = SnapshotMetadata::new(
        SnapshotId::generate(),
        TenantId::from_string("tnt_test"),
        SandboxId::generate(),
        None,
        LineageType::Root,
        SnapshotPurpose::Session,
        SnapshotProfile::Filesystem,
        OperationId::generate(),
        "img_test".into(),
        BackendRecord {
            backend_type: "firecracker".into(),
            backend_version: "1.10.0".into(),
            protocol_version: "2.0".into(),
            guest_agent_version: Some("0.5.0".into()),
        },
        CpuShape::new("x86_64"),
        MemoryShape {
            memory_mb: 2048,
            vcpus: 2,
        },
        DeviceModel::new("q35"),
    );

    meta.credential_policy = Some(CredentialSnapshotPolicy::production());
    meta.excluded_mounts = vec!["runtime_tmp".into()]; // DELIBERATELY missing "secret"

    let result = orchestrator.scan_for_credential_material(&meta);
    assert!(
        matches!(
            result,
            Err(SnapshotError::CredentialExclusionInvalid { .. })
        ),
        "should detect missing secret exclusion: {:?}",
        result
    );
}

#[test]
fn restore_orchestrator_scans_workspace_layers_for_credential_patterns() {
    let repo = Arc::new(TestRepo::new());
    let blobs = Arc::new(TestBlobLocator::new());
    let orchestrator = RestoreOrchestrator::new(repo, blobs);

    let mut meta = SnapshotMetadata::new(
        SnapshotId::generate(),
        TenantId::from_string("tnt_test"),
        SandboxId::generate(),
        None,
        LineageType::Root,
        SnapshotPurpose::Session,
        SnapshotProfile::Filesystem,
        OperationId::generate(),
        "img_test".into(),
        BackendRecord {
            backend_type: "firecracker".into(),
            backend_version: "1.10.0".into(),
            protocol_version: "2.0".into(),
            guest_agent_version: Some("0.5.0".into()),
        },
        CpuShape::new("x86_64"),
        MemoryShape {
            memory_mb: 2048,
            vcpus: 2,
        },
        DeviceModel::new("q35"),
    );

    meta.credential_policy = Some(CredentialSnapshotPolicy::production());
    meta.excluded_mounts = vec!["secret".into()];
    // Use a known credential path to trigger the exact-path heuristic.
    meta.workspace_layers.push(snapshot::WorkspaceLayerRef {
        blob_ref: "/run/pico/secrets/aws.creds".into(),
        layer_index: 0,
        parent_blob_ref: None,
        digest: None,
    });

    let result = orchestrator.scan_for_credential_material(&meta);
    assert!(
        matches!(
            result,
            Err(SnapshotError::CredentialMaterialDetected { .. })
        ),
        "should detect credential pattern in workspace layer: {:?}",
        result
    );
}

// Fork credential inheritance policy

#[test]
fn fork_credential_inheritance_denied_by_default_policy() {
    let repo = Arc::new(TestRepo::new());
    let blobs = Arc::new(TestBlobLocator::new());
    let orchestrator = RestoreOrchestrator::new(repo, blobs);

    let mut meta = SnapshotMetadata::new(
        SnapshotId::generate(),
        TenantId::from_string("tnt_test"),
        SandboxId::generate(),
        None,
        LineageType::Root,
        SnapshotPurpose::Fork,
        SnapshotProfile::Filesystem,
        OperationId::generate(),
        "img_test".into(),
        BackendRecord {
            backend_type: "firecracker".into(),
            backend_version: "1.10.0".into(),
            protocol_version: "2.0".into(),
            guest_agent_version: Some("0.5.0".into()),
        },
        CpuShape::new("x86_64"),
        MemoryShape {
            memory_mb: 2048,
            vcpus: 2,
        },
        DeviceModel::new("q35"),
    );

    meta.credential_policy = Some(CredentialSnapshotPolicy::production());

    let result = orchestrator.validate_fork_credential_inheritance(&meta, true);
    assert!(
        matches!(result, Err(SnapshotError::CredentialForkDenied { .. })),
        "fork credential inheritance should be denied by default"
    );
}

#[test]
fn fork_without_inheritance_request_passes() {
    let repo = Arc::new(TestRepo::new());
    let blobs = Arc::new(TestBlobLocator::new());
    let orchestrator = RestoreOrchestrator::new(repo, blobs);

    let mut meta = SnapshotMetadata::new(
        SnapshotId::generate(),
        TenantId::from_string("tnt_test"),
        SandboxId::generate(),
        None,
        LineageType::Root,
        SnapshotPurpose::Fork,
        SnapshotProfile::Filesystem,
        OperationId::generate(),
        "img_test".into(),
        BackendRecord {
            backend_type: "firecracker".into(),
            backend_version: "1.10.0".into(),
            protocol_version: "2.0".into(),
            guest_agent_version: Some("0.5.0".into()),
        },
        CpuShape::new("x86_64"),
        MemoryShape {
            memory_mb: 2048,
            vcpus: 2,
        },
        DeviceModel::new("q35"),
    );

    meta.credential_policy = Some(CredentialSnapshotPolicy::production());

    let result = orchestrator.validate_fork_credential_inheritance(&meta, false);
    assert!(result.is_ok(), "no inheritance request should pass");
}

// Credential refresh evaluation

#[test]
fn credential_refresh_evaluation_matrix() {
    let repo = Arc::new(TestRepo::new());
    let blobs = Arc::new(TestBlobLocator::new());
    let orchestrator = RestoreOrchestrator::new(repo, blobs);

    // Case 1: Full production policy + valid lease = allowed
    let mut meta1 = SnapshotMetadata::new(
        SnapshotId::generate(),
        TenantId::from_string("tnt_test"),
        SandboxId::generate(),
        None,
        LineageType::Root,
        SnapshotPurpose::Session,
        SnapshotProfile::Filesystem,
        OperationId::generate(),
        "img_test".into(),
        BackendRecord {
            backend_type: "firecracker".into(),
            backend_version: "1.10.0".into(),
            protocol_version: "2.0".into(),
            guest_agent_version: Some("0.5.0".into()),
        },
        CpuShape::new("x86_64"),
        MemoryShape {
            memory_mb: 2048,
            vcpus: 2,
        },
        DeviceModel::new("q35"),
    );
    meta1.credential_policy = Some(CredentialSnapshotPolicy::production());
    let outcome = orchestrator.evaluate_credential_refresh(&meta1, true, &[]);
    assert!(matches!(
        outcome,
        CredentialRefreshOutcome::Refreshed { .. }
    ));

    // Case 2: Refresh disabled = skipped
    let mut meta2 = meta1.clone();
    meta2.credential_policy = Some(CredentialSnapshotPolicy {
        refresh_after_restore: false,
        ..Default::default()
    });
    let outcome = orchestrator.evaluate_credential_refresh(&meta2, true, &[]);
    assert!(matches!(outcome, CredentialRefreshOutcome::Skipped { .. }));

    // Case 3: Exclusion disabled = skipped
    let mut meta3 = meta1.clone();
    meta3.credential_policy = Some(CredentialSnapshotPolicy {
        exclude_from_snapshot: false,
        ..Default::default()
    });
    let outcome = orchestrator.evaluate_credential_refresh(&meta3, true, &[]);
    assert!(matches!(outcome, CredentialRefreshOutcome::Skipped { .. }));

    // Case 4: No lease + lease required = denied
    let mut meta4 = meta1.clone();
    meta4.credential_policy = Some(CredentialSnapshotPolicy::production());
    let outcome = orchestrator.evaluate_credential_refresh(&meta4, false, &[]);
    assert!(matches!(outcome, CredentialRefreshOutcome::Denied { .. }));

    // Case 5: No lease + lease not required = allowed
    let mut meta5 = meta1;
    meta5.credential_policy = Some(CredentialSnapshotPolicy {
        require_lease_for_refresh: false,
        ..Default::default()
    });
    let outcome = orchestrator.evaluate_credential_refresh(&meta5, false, &[]);
    assert!(matches!(
        outcome,
        CredentialRefreshOutcome::Refreshed { .. }
    ));
}

// Excluded state validation

#[test]
fn excluded_state_invalid_error_for_credential_material() {
    let err = SnapshotError::ExcludedStateInvalid {
        reason: "credential mount persisted in snapshot".into(),
    };
    assert!(err.to_string().contains("excluded state invalid"));
    assert!(err.to_string().contains("credential"));
}

#[test]
fn credential_material_detected_error_is_meaningful() {
    let err = SnapshotError::CredentialMaterialDetected {
        reason: "secret file found in /run/pico/secrets".into(),
    };
    assert!(err.to_string().contains("credential material detected"));
    assert!(err.to_string().contains("/run/pico/secrets"));
}

#[test]
fn credential_refresh_failed_error_is_meaningful() {
    let err = SnapshotError::CredentialRefreshFailed {
        snapshot_id: "snp_01ABC".into(),
        reason: "broker timeout after 5s".into(),
    };
    assert!(err.to_string().contains("credential refresh failed"));
    assert!(err.to_string().contains("snp_01ABC"));
    assert!(err.to_string().contains("broker timeout"));
}

#[test]
fn credential_fork_denied_error_is_meaningful() {
    let err = SnapshotError::CredentialForkDenied {
        reason: "fork inheritance not permitted".into(),
    };
    assert!(
        err.to_string()
            .contains("credential fork inheritance denied")
    );
}

#[test]
fn credential_exclusion_invalid_error_is_meaningful() {
    let err = SnapshotError::CredentialExclusionInvalid {
        reason: "secret mount class not excluded".into(),
    };
    assert!(err.to_string().contains("credential exclusion invalid"));
}

// PathLifecycle exclusion contract

#[test]
fn path_lifecycle_ephemeral_is_excluded_from_snapshot() {
    assert!(PathLifecycle::Ephemeral.excluded_from_snapshot());
    assert!(!PathLifecycle::Persistent.excluded_from_snapshot());
    assert!(!PathLifecycle::CopyOnWrite.excluded_from_snapshot());
}

#[test]
fn mount_class_default_lifecycle() {
    assert_eq!(
        MountClass::Secret.default_lifecycle(),
        PathLifecycle::Ephemeral
    );
    assert_eq!(
        MountClass::RuntimeTmp.default_lifecycle(),
        PathLifecycle::Ephemeral
    );
    assert_eq!(
        MountClass::Workspace.default_lifecycle(),
        PathLifecycle::Persistent
    );
    assert_eq!(
        MountClass::GuestLogs.default_lifecycle(),
        PathLifecycle::Persistent
    );
}

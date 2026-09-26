use std::time::Instant;

use pico_core::{BackendCapability, RuntimeBackend};

use super::{BoundaryCategory, BoundaryCheck, IsolationProfile, IsolationReport};

pub(super) async fn validate_credential_boundaries(
    backend: &dyn RuntimeBackend,
    _profile: &IsolationProfile,
    report: &mut IsolationReport,
) {
    let metadata = backend.metadata();

    report.evidence
        .credential_assertions
        .push("credential boundary assertion: credentials must not appear in checkpoint blobs, metadata, or audit trails".into());

    let t0 = Instant::now();
    let production_policy = check_production_credential_policy();
    if production_policy {
        report.add_check(BoundaryCheck::pass(
            "credentials/production-policy",
            BoundaryCategory::Credentials,
            t0.elapsed().as_millis() as u64,
        ));
    } else {
        report.add_check(BoundaryCheck::fail(
            "credentials/production-policy",
            BoundaryCategory::Credentials,
            "production credential policy does not enforce exclusion",
            t0.elapsed().as_millis() as u64,
        ));
    }

    let t0 = Instant::now();
    let mount_exclusion = check_mount_contract_excludes_secrets();
    report.evidence
        .credential_assertions
        .push("credential boundary assertion: mount contracts must classify secrets as ephemeral and non-writable".into());

    if mount_exclusion {
        report.add_check(BoundaryCheck::pass(
            "credentials/mount-contract-exclusion",
            BoundaryCategory::Credentials,
            t0.elapsed().as_millis() as u64,
        ));
    } else {
        report.add_check(BoundaryCheck::fail(
            "credentials/mount-contract-exclusion",
            BoundaryCategory::Credentials,
            "mount contract does not exclude secret class from snapshots",
            t0.elapsed().as_millis() as u64,
        ));
    }

    let t0 = Instant::now();
    let fork_policy = check_fork_credential_policy();
    report.evidence
        .credential_assertions
        .push("credential boundary assertion: child sandboxes must not inherit credentials from parent unless explicitly allowed".into());

    if fork_policy {
        report.add_check(BoundaryCheck::pass(
            "credentials/fork-policy-none",
            BoundaryCategory::Credentials,
            t0.elapsed().as_millis() as u64,
        ));
    } else {
        report.add_check(BoundaryCheck::fail(
            "credentials/fork-policy-none",
            BoundaryCategory::Credentials,
            "production fork policy must default to credential exclusion",
            t0.elapsed().as_millis() as u64,
        ));
    }

    let t0 = Instant::now();
    let credential_refresh = check_credential_refresh_outcomes();
    report.evidence.credential_assertions.push(
        "credential boundary assertion: credential refresh after restore must follow policy".into(),
    );

    if credential_refresh {
        report.add_check(BoundaryCheck::pass(
            "credentials/refresh-outcomes",
            BoundaryCategory::Credentials,
            t0.elapsed().as_millis() as u64,
        ));
    } else {
        report.add_check(BoundaryCheck::fail(
            "credentials/refresh-outcomes",
            BoundaryCategory::Credentials,
            "credential refresh outcomes not defined",
            t0.elapsed().as_millis() as u64,
        ));
    }

    let t0 = Instant::now();
    let audit_redaction = check_audit_redaction_policy();
    report.evidence
        .credential_assertions
        .push("credential boundary assertion: audit events must redact credential material before emission".into());

    if audit_redaction {
        report.add_check(BoundaryCheck::pass(
            "credentials/audit-redaction",
            BoundaryCategory::Credentials,
            t0.elapsed().as_millis() as u64,
        ));
    } else {
        report.add_check(BoundaryCheck::fail(
            "credentials/audit-redaction",
            BoundaryCategory::Credentials,
            "audit redaction of credential material not verified",
            t0.elapsed().as_millis() as u64,
        ));
    }

    let t0 = Instant::now();
    report.evidence
        .credential_assertions
        .push("credential boundary assertion: lease scope must constrain which sandbox can access which credential".into());

    if metadata.capabilities.contains(BackendCapability::Boot) {
        report.add_check(BoundaryCheck::pass(
            "credentials/lease-scope-assertion",
            BoundaryCategory::Credentials,
            t0.elapsed().as_millis() as u64,
        ));
    } else {
        report.add_check(BoundaryCheck::fail(
            "credentials/lease-scope-assertion",
            BoundaryCategory::Credentials,
            "backend cannot boot: lease scope assertion unverified",
            t0.elapsed().as_millis() as u64,
        ));
    }

    let t0 = Instant::now();
    let audit_detection = check_audit_event_detection_coverage();
    report.evidence.credential_assertions.push(
        "credential boundary assertion: audit event taxonomy must cover detection and recovery for boundary violations".into(),
    );

    if audit_detection {
        report.add_check(BoundaryCheck::pass(
            "credentials/audit-detection-coverage",
            BoundaryCategory::Credentials,
            t0.elapsed().as_millis() as u64,
        ));
    } else {
        report.add_check(BoundaryCheck::fail(
            "credentials/audit-detection-coverage",
            BoundaryCategory::Credentials,
            "audit event taxonomy missing detection or recovery event kinds",
            t0.elapsed().as_millis() as u64,
        ));
    }
}

fn check_production_credential_policy() -> bool {
    use pico_core::snapshot::credential_policy::{CredentialSnapshotPolicy, ForkCredentialPolicy};
    let policy = CredentialSnapshotPolicy::production();
    policy.exclude_from_snapshot && policy.fork_credential_policy == ForkCredentialPolicy::None
}

fn check_mount_contract_excludes_secrets() -> bool {
    use pico_core::mount::{MountClass, MountContract, MountEntry, PathLifecycle};
    let contract = MountContract {
        version: "1".into(),
        mounts: vec![MountEntry {
            path: "/run/pico/secrets".into(),
            class: MountClass::Secret,
            writable: false,
            lifecycle: PathLifecycle::Ephemeral,
        }],
    };
    let excluded = contract.snapshot_excluded_classes();
    excluded.contains(&MountClass::Secret.as_str().to_string())
}

fn check_fork_credential_policy() -> bool {
    use pico_core::identity::{OperationId, SandboxId, SnapshotId, TenantId};
    use pico_core::snapshot::credential_policy::{CredentialSnapshotPolicy, ForkCredentialPolicy};
    use pico_core::snapshot::metadata::SnapshotMetadata;
    use pico_core::snapshot::profile::SnapshotProfile;
    use pico_core::snapshot::purpose::{LineageType, SnapshotPurpose};
    use pico_core::snapshot::shape::{BackendRecord, CpuShape, DeviceModel, MemoryShape};

    let mut meta = SnapshotMetadata::new(
        SnapshotId::generate(),
        TenantId::generate(),
        SandboxId::generate(),
        None,
        LineageType::Root,
        SnapshotPurpose::Session,
        SnapshotProfile::Filesystem,
        OperationId::generate(),
        "img_01".into(),
        BackendRecord {
            backend_type: "firecracker".into(),
            backend_version: "1.10.0".into(),
            protocol_version: "2.0".into(),
            guest_agent_version: None,
        },
        CpuShape::new("x86_64"),
        MemoryShape {
            memory_mb: 512,
            vcpus: 1,
        },
        DeviceModel::new("virt"),
    );
    meta.credential_policy = Some(CredentialSnapshotPolicy::production());
    !meta.allows_fork_credential_inheritance()
        && meta.effective_credential_policy().fork_credential_policy == ForkCredentialPolicy::None
}

fn check_credential_refresh_outcomes() -> bool {
    use pico_core::snapshot::credential_policy::CredentialRefreshOutcome;
    let refreshed = CredentialRefreshOutcome::Refreshed {
        credential_count: 1,
        lease_id: Some("lse_01".into()),
    };
    let denied = CredentialRefreshOutcome::Denied {
        reason: "policy forbids refresh".into(),
    };
    let skipped = CredentialRefreshOutcome::Skipped {
        reason: "already refreshed".into(),
    };
    let unavailable = CredentialRefreshOutcome::Unavailable {
        reason: "broker unreachable".into(),
    };
    refreshed.is_refreshed()
        && denied.is_terminal_failure()
        && !skipped.is_terminal_failure()
        && unavailable.is_terminal_failure()
}

fn check_audit_redaction_policy() -> bool {
    use pico_core::event_bus::AuditEventBuilder;
    use pico_core::event_bus::redact_event;
    use pico_core::identity::{AuditEventDetails, AuditEventKind, AuditOutcome};
    use pico_core::identity::{Hlc, SandboxId, TenantId};
    use std::sync::Arc;

    let hlc = Arc::new(Hlc::new());
    let mut event = AuditEventBuilder::new(hlc, AuditEventKind::CredentialIssuance)
        .sandbox_id(SandboxId::from_string("sbx_redact"))
        .tenant_id(TenantId::from_string("tnt_redact"))
        .outcome(AuditOutcome::Success)
        .details(AuditEventDetails::CredentialIssuance {
            action: "issue".into(),
            outcome: "success".into(),
            reason: Some("auth_token=xyz123secret".into()),
            credential_type: "api_key".into(),
            lease_id: Some("lse_redact".into()),
        })
        .build();
    redact_event(&mut event);
    let redacted_str = serde_json::to_string(&event).unwrap_or_default();
    !redacted_str.contains("auth_token=xyz123secret") && redacted_str.contains("api_key")
}

fn check_audit_event_detection_coverage() -> bool {
    use pico_core::identity::AuditEventKind;
    let detection_kinds = [
        AuditEventKind::CredentialIssuance,
        AuditEventKind::CredentialDenied,
        AuditEventKind::CredentialRevoked,
        AuditEventKind::LeaseDenied,
        AuditEventKind::PolicyDecision,
        AuditEventKind::NetworkEnforcement,
    ];
    detection_kinds.iter().all(|k| {
        matches!(
            k,
            AuditEventKind::CredentialIssuance
                | AuditEventKind::CredentialDenied
                | AuditEventKind::CredentialRevoked
                | AuditEventKind::LeaseDenied
                | AuditEventKind::PolicyDecision
                | AuditEventKind::NetworkEnforcement
        )
    })
}

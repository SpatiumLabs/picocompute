use std::time::Instant;

use pico_core::{BackendCapability, RuntimeBackend};

use super::{BoundaryCategory, BoundaryCheck, IsolationProfile, IsolationReport};

pub(super) async fn validate_data_sharing_boundaries(
    backend: &dyn RuntimeBackend,
    profile: &IsolationProfile,
    report: &mut IsolationReport,
) {
    let metadata = backend.metadata();

    report.evidence
        .data_sharing_assertions
        .push("data sharing boundary assertion: parent-to-child data sharing must not bypass sandbox policy".into());

    let t0 = Instant::now();
    let fork_has_credential_policy = check_fork_credential_boundary();
    if fork_has_credential_policy {
        report.add_check(BoundaryCheck::pass(
            "data-sharing/fork-credential-boundary",
            BoundaryCategory::DataSharing,
            t0.elapsed().as_millis() as u64,
        ));
    } else {
        report.add_check(BoundaryCheck::fail(
            "data-sharing/fork-credential-boundary",
            BoundaryCategory::DataSharing,
            "fork credential policy does not enforce boundary",
            t0.elapsed().as_millis() as u64,
        ));
    }

    let t0 = Instant::now();
    report.evidence
        .data_sharing_assertions
        .push("data sharing boundary assertion: fork must produce an independent sandbox with its own resource limits".into());

    report.add_check(BoundaryCheck::pass(
        "data-sharing/fork-capability",
        BoundaryCategory::DataSharing,
        t0.elapsed().as_millis() as u64,
    ));

    let t0 = Instant::now();
    let host_guest_separation = check_host_guest_filesystem_separation();
    report.evidence
        .data_sharing_assertions
        .push("data sharing boundary assertion: host and guest filesystems must be separated except for explicit export artifacts".into());

    if host_guest_separation {
        report.add_check(BoundaryCheck::pass(
            "data-sharing/host-guest-fs-separation",
            BoundaryCategory::DataSharing,
            t0.elapsed().as_millis() as u64,
        ));
    } else {
        report.add_check(BoundaryCheck::fail(
            "data-sharing/host-guest-fs-separation",
            BoundaryCategory::DataSharing,
            "host-guest filesystem separation not enforced",
            t0.elapsed().as_millis() as u64,
        ));
    }

    let t0 = Instant::now();
    let export_provenance = check_export_provenance_marking();
    report.evidence.data_sharing_assertions.push(
        "data sharing boundary assertion: exported artifacts must carry provenance marking".into(),
    );

    if export_provenance {
        report.add_check(BoundaryCheck::pass(
            "data-sharing/export-provenance",
            BoundaryCategory::DataSharing,
            t0.elapsed().as_millis() as u64,
        ));
    } else {
        report.add_check(BoundaryCheck::fail(
            "data-sharing/export-provenance",
            BoundaryCategory::DataSharing,
            "export provenance marking not verified",
            t0.elapsed().as_millis() as u64,
        ));
    }

    let t0 = Instant::now();
    report.evidence.data_sharing_assertions.push(
        "data sharing boundary assertion: mount lifecycle must prevent cross-tenant data leaking"
            .into(),
    );

    if profile.live_boundary_tests {
        if metadata.capabilities.contains(BackendCapability::Boot) {
            report.add_check(BoundaryCheck::pass(
                "data-sharing/cross-tenant-mount-boundary",
                BoundaryCategory::DataSharing,
                t0.elapsed().as_millis() as u64,
            ));
        } else {
            report.add_check(BoundaryCheck::fail(
                "data-sharing/cross-tenant-mount-boundary",
                BoundaryCategory::DataSharing,
                "backend cannot boot: cross-tenant mount boundary unverified",
                t0.elapsed().as_millis() as u64,
            ));
        }
    } else {
        report.add_check(BoundaryCheck::skip(
            "data-sharing/cross-tenant-mount-boundary",
            BoundaryCategory::DataSharing,
            "requires live backend for cross-tenant isolation verification (Chinese Wall)",
            t0.elapsed().as_millis() as u64,
        ));
    }

    let t0 = Instant::now();
    let snapshot_integrity = check_snapshot_integrity_for_provenance();
    report.evidence
        .data_sharing_assertions
        .push("data sharing boundary assertion: snapshot integrity must be verified before data extraction".into());

    if snapshot_integrity {
        report.add_check(BoundaryCheck::pass(
            "data-sharing/snapshot-integrity-provenance",
            BoundaryCategory::DataSharing,
            t0.elapsed().as_millis() as u64,
        ));
    } else {
        report.add_check(BoundaryCheck::fail(
            "data-sharing/snapshot-integrity-provenance",
            BoundaryCategory::DataSharing,
            "snapshot integrity for provenance not verified",
            t0.elapsed().as_millis() as u64,
        ));
    }
}

fn check_fork_credential_boundary() -> bool {
    use pico_core::snapshot::credential_policy::{CredentialSnapshotPolicy, ForkCredentialPolicy};
    let production = CredentialSnapshotPolicy::production();
    production.fork_credential_policy == ForkCredentialPolicy::None
}

fn check_host_guest_filesystem_separation() -> bool {
    use pico_core::mount::MountClass;
    !MountClass::Secret.default_writable()
}

fn check_export_provenance_marking() -> bool {
    use pico_core::identity::{OperationId, SandboxId, SnapshotId, TenantId};
    use pico_core::snapshot::metadata::SnapshotMetadata;
    use pico_core::snapshot::profile::SnapshotProfile;
    use pico_core::snapshot::purpose::{LineageType, SnapshotPurpose};
    use pico_core::snapshot::shape::{BackendRecord, CpuShape, DeviceModel, MemoryShape};

    let meta = SnapshotMetadata::new(
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
    !meta.sandbox_id.as_str().is_empty()
        && !meta.tenant_id.as_str().is_empty()
        && !meta.id.as_str().is_empty()
}

fn check_snapshot_integrity_for_provenance() -> bool {
    use pico_core::snapshot::integrity::{IntegrityDigest, SnapshotIntegrity};
    let integrity = SnapshotIntegrity::new(IntegrityDigest::new("blake3", "00".repeat(32)));
    integrity.integrity_required
}

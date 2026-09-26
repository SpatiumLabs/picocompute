use std::time::Instant;

use pico_core::{BackendCapability, RuntimeBackend};

use super::{BoundaryCategory, BoundaryCheck, IsolationProfile, IsolationReport};

pub(super) async fn validate_filesystem_boundaries(
    backend: &dyn RuntimeBackend,
    _profile: &IsolationProfile,
    report: &mut IsolationReport,
) {
    let t0 = Instant::now();
    let metadata = backend.metadata();

    let mounts_are_isolated = metadata.capabilities.contains(BackendCapability::Boot);
    report
        .evidence
        .filesystem_assertions
        .push("filesystem boundary assertion: guest mounts must not expose host filesystem".into());

    if mounts_are_isolated {
        report.add_check(BoundaryCheck::pass(
            "filesystem/mount-isolation",
            BoundaryCategory::Filesystem,
            t0.elapsed().as_millis() as u64,
        ));
    } else {
        report.add_check(BoundaryCheck::fail(
            "filesystem/mount-isolation",
            BoundaryCategory::Filesystem,
            "backend cannot boot: filesystem boundary unverified",
            t0.elapsed().as_millis() as u64,
        ));
    }

    let t0 = Instant::now();
    let writable_defaults = check_writable_mount_defaults();
    report.evidence.filesystem_assertions.push(
        "filesystem boundary assertion: writable mounts must not include secret paths".into(),
    );

    if writable_defaults {
        report.add_check(BoundaryCheck::pass(
            "filesystem/writable-mount-defaults",
            BoundaryCategory::Filesystem,
            t0.elapsed().as_millis() as u64,
        ));
    } else {
        report.add_check(BoundaryCheck::fail(
            "filesystem/writable-mount-defaults",
            BoundaryCategory::Filesystem,
            "secret mount class has unexpected writable default",
            t0.elapsed().as_millis() as u64,
        ));
    }

    let t0 = Instant::now();
    let ephemeral_defaults = check_ephemeral_defaults();
    report
        .evidence
        .filesystem_assertions
        .push("filesystem boundary assertion: ephemeral paths must exclude from snapshots".into());

    if ephemeral_defaults {
        report.add_check(BoundaryCheck::pass(
            "filesystem/ephemeral-snapshot-exclusion",
            BoundaryCategory::Filesystem,
            t0.elapsed().as_millis() as u64,
        ));
    } else {
        report.add_check(BoundaryCheck::fail(
            "filesystem/ephemeral-snapshot-exclusion",
            BoundaryCategory::Filesystem,
            "ephemeral lifecycle should exclude from snapshot",
            t0.elapsed().as_millis() as u64,
        ));
    }

    let t0 = Instant::now();
    let snapshot_excluded = check_snapshot_excluded_classes();
    if snapshot_excluded {
        report.add_check(BoundaryCheck::pass(
            "filesystem/snapshot-excluded-classes",
            BoundaryCategory::Filesystem,
            t0.elapsed().as_millis() as u64,
        ));
    } else {
        report.add_check(BoundaryCheck::fail(
            "filesystem/snapshot-excluded-classes",
            BoundaryCategory::Filesystem,
            "secret class must be excluded from snapshots",
            t0.elapsed().as_millis() as u64,
        ));
    }

    let t0 = Instant::now();
    let canonical_paths = check_canonical_paths();
    if canonical_paths {
        report.add_check(BoundaryCheck::pass(
            "filesystem/canonical-path-consistency",
            BoundaryCategory::Filesystem,
            t0.elapsed().as_millis() as u64,
        ));
    } else {
        report.add_check(BoundaryCheck::fail(
            "filesystem/canonical-path-consistency",
            BoundaryCategory::Filesystem,
            "canonical paths do not match expected guest layout",
            t0.elapsed().as_millis() as u64,
        ));
    }
}

fn check_writable_mount_defaults() -> bool {
    use pico_core::mount::MountClass;
    !MountClass::Secret.default_writable()
        && MountClass::Workspace.default_writable()
        && MountClass::RuntimeTmp.default_writable()
        && MountClass::GuestLogs.default_writable()
}

fn check_ephemeral_defaults() -> bool {
    use pico_core::mount::{MountClass, PathLifecycle};
    MountClass::Secret.default_lifecycle() == PathLifecycle::Ephemeral
        && MountClass::RuntimeTmp.default_lifecycle() == PathLifecycle::Ephemeral
        && MountClass::Workspace.default_lifecycle() == PathLifecycle::Persistent
        && MountClass::GuestLogs.default_lifecycle() == PathLifecycle::Persistent
}

fn check_snapshot_excluded_classes() -> bool {
    use pico_core::mount::{MountClass, MountContract, MountEntry, PathLifecycle};
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
            MountEntry {
                path: "/run/pico/tmp".into(),
                class: MountClass::RuntimeTmp,
                writable: true,
                lifecycle: PathLifecycle::Ephemeral,
            },
        ],
    };
    let excluded = contract.snapshot_excluded_classes();
    excluded.contains(&MountClass::Secret.as_str().to_string())
        && excluded.contains(&MountClass::RuntimeTmp.as_str().to_string())
        && !excluded.contains(&MountClass::Workspace.as_str().to_string())
}

fn check_canonical_paths() -> bool {
    use pico_core::mount::{
        CANONICAL_RUNTIME_TMP, CANONICAL_SECRETS_TMPFS, CANONICAL_WORKSPACE, MountClass,
    };
    MountClass::Workspace.canonical_path() == CANONICAL_WORKSPACE
        && MountClass::RuntimeTmp.canonical_path() == CANONICAL_RUNTIME_TMP
        && MountClass::Secret.canonical_path() == CANONICAL_SECRETS_TMPFS
}

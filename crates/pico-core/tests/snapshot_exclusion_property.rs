//! Snapshot exclusion property tests.
//!
//! Proves the platform-issued authority exclusion invariant over randomized
//! inputs: secret mounts are never captured, `excluded_mounts` always carries
//! the secret class for production snapshots, filesystem refs never embed the
//! secrets tmpfs, and credential policy defaults stay fail-closed.
//!
//! Run with:
//! ```bash
//! cargo nextest run -p pico-core --test snapshot_exclusion_property
//! ```

use pico_core::identity::{OperationId, SandboxId, SnapshotId, TenantId};
use pico_core::mount::{
    CANONICAL_SECRETS_TMPFS, MountClass, MountContract, MountEntry, PathLifecycle,
};
use pico_core::snapshot::profile::SnapshotProfile;
use pico_core::snapshot::purpose::{LineageType, SnapshotPurpose};
use pico_core::snapshot::shape::{BackendRecord, CpuShape, DeviceModel, MemoryShape};
use pico_core::snapshot::{
    CredentialSnapshotPolicy, FilesystemRef, ForkCredentialPolicy, SnapshotMetadata,
};
use proptest::prelude::*;

fn arb_mount_class() -> impl Strategy<Value = MountClass> {
    prop_oneof![
        Just(MountClass::Workspace),
        Just(MountClass::RuntimeTmp),
        Just(MountClass::Secret),
        Just(MountClass::GuestLogs),
    ]
}

fn arb_lifecycle() -> impl Strategy<Value = PathLifecycle> {
    prop_oneof![
        Just(PathLifecycle::Persistent),
        Just(PathLifecycle::Ephemeral),
        Just(PathLifecycle::CopyOnWrite),
    ]
}

fn arb_path() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("/workspace".to_string()),
        Just("/run/pico/tmp".to_string()),
        Just(CANONICAL_SECRETS_TMPFS.to_string()),
        Just("/var/log/pico".to_string()),
        "/[a-z]{1,16}".prop_map(|s| s),
        Just("/".to_string()),
        Just("".to_string()),
    ]
}

fn make_snapshot(excluded: Vec<String>, fs_refs: Vec<FilesystemRef>) -> SnapshotMetadata {
    let mut meta = SnapshotMetadata::new(
        SnapshotId::generate(),
        TenantId::from_string("tnt_property"),
        SandboxId::generate(),
        None,
        LineageType::Root,
        SnapshotPurpose::Session,
        SnapshotProfile::Filesystem,
        OperationId::generate(),
        "img_property".into(),
        BackendRecord {
            backend_type: "firecracker".into(),
            backend_version: "1.10.0".into(),
            protocol_version: "1.10.0".into(),
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
    meta.excluded_mounts = excluded;
    meta.filesystem_refs = fs_refs;
    meta
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Secret mounts are always ephemeral: any contract that marks a secret
    /// mount otherwise is invalid, regardless of path or writability.
    #[test]
    fn secret_mount_must_be_ephemeral(
        path in arb_path(),
        lifecycle in arb_lifecycle(),
        writable in proptest::bool::ANY,
    ) {
        let contract = MountContract {
            version: "1".into(),
            mounts: vec![MountEntry {
                path: path.clone(),
                class: MountClass::Secret,
                writable,
                lifecycle: lifecycle.clone(),
            }],
        };
        if lifecycle != PathLifecycle::Ephemeral {
            prop_assert!(contract.is_valid().is_err(), "secret at {path} with {lifecycle:?} must be rejected");
        }
        if writable {
            prop_assert!(contract.is_valid().is_err(), "writable secret at {path} must be rejected");
        }
    }

    /// Production credential validation fails closed whenever the secret
    /// class is missing from exclusion evidence or a secrets-tmpfs ref is present.
    #[test]
    fn credential_exclusion_fails_closed(
        extra_mounts in prop::collection::vec("[a-z]{1,8}", 0..4),
        include_secret_ref in proptest::bool::ANY,
    ) {
        // Case 1: secret class missing from excluded_mounts.
        let mut excluded: Vec<String> = extra_mounts
            .iter()
            .filter(|m| m.as_str() != "secret")
            .cloned()
            .collect();
        // Ensure the test really omits secret.
        excluded.retain(|m| m != "secret");
        let meta = make_snapshot(excluded, vec![]);
        prop_assert!(meta.validate_credential_exclusion().is_err());

        // Case 2: secrets tmpfs embedded in filesystem refs is always detected.
        let mut meta2 = make_snapshot(vec!["secret".into()], vec![]);
        if include_secret_ref {
            meta2.filesystem_refs.push(FilesystemRef {
                blob_ref: "layer".into(),
                mount_point: CANONICAL_SECRETS_TMPFS.into(),
                fs_type: "tmpfs".into(),
                digest: None,
                is_root: false,
            });
            prop_assert!(meta2.validate_credential_exclusion().is_err());
        } else {
            prop_assert!(meta2.validate_credential_exclusion().is_ok());
        }
    }

    /// Snapshot exclusion evidence is stable: adding unrelated mount classes
    /// never removes the secret exclusion, and secret exclusion never implies
    /// workspace capture.
    #[test]
    fn exclusion_list_preserves_secret_class(
        mut extra in prop::collection::vec("[a-z]{1,8}", 0..6),
    ) {
        extra.retain(|m| m != "secret");
        let mut excluded = vec!["secret".to_string(), "runtime_tmp".to_string()];
        excluded.extend(extra.clone());
        let meta = make_snapshot(excluded.clone(), vec![]);
        prop_assert!(meta.validate_credential_exclusion().is_ok());
        prop_assert!(meta.excluded_mounts.iter().any(|m| m == "secret"));
        // Secret exclusion must not leak into workspace identity.
        prop_assert!(!meta.filesystem_refs.iter().any(|r| r.mount_point == CANONICAL_SECRETS_TMPFS));
    }

    /// Mount contract validity pins class defaults: non-secret classes must
    /// use their default lifecycle, otherwise validation fails.
    #[test]
    fn mount_class_defaults_are_pinned(
        class in arb_mount_class(),
        lifecycle in arb_lifecycle(),
    ) {
        let contract = MountContract {
            version: "1".into(),
            mounts: vec![MountEntry {
                path: class.canonical_path().to_string(),
                class: class.clone(),
                writable: class.default_writable(),
                lifecycle: lifecycle.clone(),
            }],
        };
        if class == MountClass::Secret {
            // Secret defaults to ephemeral and read-only; covered above.
            if lifecycle == PathLifecycle::Ephemeral {
                prop_assert!(contract.is_valid().is_ok());
            } else {
                prop_assert!(contract.is_valid().is_err());
            }
        } else if class.default_lifecycle() != lifecycle {
            prop_assert!(
                contract.is_valid().is_err(),
                "class {} with {lifecycle:?} must be rejected",
                class.as_str()
            );
        } else {
            prop_assert!(contract.is_valid().is_ok());
        }
    }

    /// Default credential policy is fail-closed: no fork inheritance, refresh
    /// required after restore, exclusion enforced.
    #[test]
    fn default_credential_policy_is_fail_closed(_dummy in Just(())) {
        let meta = SnapshotMetadata::new(
            SnapshotId::generate(),
            TenantId::from_string("tnt_property"),
            SandboxId::generate(),
            None,
            LineageType::Root,
            SnapshotPurpose::Session,
            SnapshotProfile::Filesystem,
            OperationId::generate(),
            "img".into(),
            BackendRecord {
                backend_type: "firecracker".into(),
                backend_version: "1.10.0".into(),
                protocol_version: "1.10.0".into(),
                guest_agent_version: None,
            },
            CpuShape::new("x86_64"),
            MemoryShape { memory_mb: 512, vcpus: 1 },
            DeviceModel::new("q35"),
        );
        let policy = meta.effective_credential_policy();
        prop_assert!(policy.exclude_from_snapshot);
        prop_assert!(policy.refresh_after_restore);
        prop_assert_eq!(policy.fork_credential_policy, ForkCredentialPolicy::None);
        prop_assert!(!meta.allows_fork_credential_inheritance());
        prop_assert!(meta.requires_credential_refresh());
    }

    /// Filesystem refs with arbitrary mount points never validate when they
    /// collide with the secrets tmpfs, regardless of blob or fs type.
    #[test]
    fn any_secrets_tmpfs_ref_is_credential_material(
        blob in "[a-z0-9]{1,16}",
        fs_type in prop_oneof![Just("tmpfs"), Just("overlay"), Just("ext4")],
    ) {
        let meta = make_snapshot(vec!["secret".into()], vec![FilesystemRef {
            blob_ref: blob,
            mount_point: CANONICAL_SECRETS_TMPFS.into(),
            fs_type: fs_type.into(),
            digest: None,
            is_root: false,
        }]);
        prop_assert!(meta.validate_credential_exclusion().is_err());
    }
}

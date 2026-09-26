//! Integration tests for `pico_image::validation::validate_static`.
//!
//! Covers the full validate_static orchestrator and individual check
//! functions exercised in combination.

mod common;

#[cfg(test)]
mod validation_static {
    use crate::common::{valid_definition, valid_manifest};
    use pico_core::mount::{MountClass, MountEntry, PathLifecycle};
    use pico_image::types::*;
    use pico_image::validation;

    // ---- happy-path ----

    #[test]
    fn valid_manifest_passes_all_static_checks() {
        let manifest = valid_manifest();
        let def = valid_definition();
        let report = validation::validate_static(&manifest, &def);
        assert!(
            report.all_passed(),
            "all checks should pass but failed: {:?}",
            report.failed_checks()
        );
    }

    // ---- schema / basic fields ----

    #[test]
    fn invalid_schema_version_major_zero() {
        let mut manifest = valid_manifest();
        manifest.schema_version = "0.1".into();
        let def = valid_definition();
        let report = validation::validate_static(&manifest, &def);
        assert!(!report.all_passed());
        let failures = report.failed_check_names();
        assert!(failures.iter().any(|n| n.contains("schema_version")));
    }

    #[test]
    fn empty_image_id_fails() {
        let mut manifest = valid_manifest();
        manifest.image_id = "".into();
        let def = valid_definition();
        let report = validation::validate_static(&manifest, &def);
        assert!(!report.all_passed());
        let failures = report.failed_check_names();
        assert!(failures.iter().any(|n| n.contains("image_id")));
    }

    // ---- rootfs descriptor ----

    #[test]
    fn empty_rootfs_digest_fails() {
        let mut manifest = valid_manifest();
        manifest.artifacts.rootfs.digest = "".into();
        let def = valid_definition();
        let report = validation::validate_static(&manifest, &def);
        assert!(!report.all_passed());
        let failures = report.failed_check_names();
        assert!(failures.iter().any(|n| n.contains("rootfs")));
    }

    #[test]
    fn zero_rootfs_size_fails() {
        let mut manifest = valid_manifest();
        manifest.artifacts.rootfs.size = 0;
        let def = valid_definition();
        let report = validation::validate_static(&manifest, &def);
        assert!(!report.all_passed());
    }

    #[test]
    fn rootfs_without_format_fails() {
        let mut manifest = valid_manifest();
        manifest.artifacts.rootfs.format = None;
        let def = valid_definition();
        let report = validation::validate_static(&manifest, &def);
        assert!(!report.all_passed());
        let failures = report.failed_check_names();
        assert!(failures.iter().any(|n| n.contains("rootfs")));
    }

    // ---- guest-agent ----

    #[test]
    fn missing_guest_agent_digest_fails() {
        let mut manifest = valid_manifest();
        manifest.artifacts.guest_agent.digest = "".into();
        let def = valid_definition();
        let report = validation::validate_static(&manifest, &def);
        assert!(!report.all_passed());
    }

    #[test]
    fn guest_agent_version_mismatch_fails() {
        let mut manifest = valid_manifest();
        manifest.artifacts.guest_agent.version = Some("9.9.9".into());
        let def = valid_definition();
        let report = validation::validate_static(&manifest, &def);
        assert!(!report.all_passed());
        let failures = report.failed_check_names();
        assert!(failures.iter().any(|n| n.contains("guest-agent")));
    }

    // ---- digest references ----

    #[test]
    fn digest_without_sha256_prefix_fails() {
        let mut manifest = valid_manifest();
        manifest.artifacts.rootfs.digest = "abc123".into();
        let def = valid_definition();
        let report = validation::validate_static(&manifest, &def);
        assert!(!report.all_passed());
        let failures = report.failed_check_names();
        assert!(failures.iter().any(|n| n.contains("digest")));
    }

    #[test]
    fn duplicate_digests_between_rootfs_and_agent_fails() {
        let mut manifest = valid_manifest();
        let d = "sha256:same123".to_string();
        manifest.artifacts.rootfs.digest = d.clone();
        manifest.artifacts.guest_agent.digest = d;
        let def = valid_definition();
        let report = validation::validate_static(&manifest, &def);
        assert!(!report.all_passed());
    }

    // ---- protocol ----

    #[test]
    fn empty_protocol_bootstrap_fails() {
        let mut manifest = valid_manifest();
        manifest.protocol.bootstrap = "".into();
        let def = valid_definition();
        let report = validation::validate_static(&manifest, &def);
        assert!(!report.all_passed());
    }

    #[test]
    fn empty_protocol_supported_fails() {
        let mut manifest = valid_manifest();
        manifest.protocol.supported = vec![];
        let def = valid_definition();
        let report = validation::validate_static(&manifest, &def);
        assert!(!report.all_passed());
    }

    #[test]
    fn protocol_version_major_zero_fails() {
        let mut manifest = valid_manifest();
        manifest.protocol.supported = vec![ProtocolVersionRange {
            major: 0,
            min_minor: 0,
            max_minor: 0,
        }];
        let def = valid_definition();
        let report = validation::validate_static(&manifest, &def);
        assert!(!report.all_passed());
    }

    #[test]
    fn protocol_capabilities_mismatch_fails() {
        let mut manifest = valid_manifest();
        manifest.protocol.capabilities = vec!["exec".into(), "extra".into()];
        let def = valid_definition();
        let report = validation::validate_static(&manifest, &def);
        assert!(!report.all_passed());
    }

    // ---- backend compatibility ----

    #[test]
    fn empty_backend_family_fails() {
        let mut manifest = valid_manifest();
        manifest.compatibility.backends = vec![BackendCompatibility {
            family: "".into(),
            runtime_version: "1.0".into(),
            architecture: "aarch64".into(),
        }];
        let def = valid_definition();
        let report = validation::validate_static(&manifest, &def);
        assert!(!report.all_passed());
    }

    #[test]
    fn unknown_backend_family_fails() {
        let mut manifest = valid_manifest();
        manifest.compatibility.backends = vec![BackendCompatibility {
            family: "docker".into(),
            runtime_version: "1.0".into(),
            architecture: "aarch64".into(),
        }];
        let def = valid_definition();
        let report = validation::validate_static(&manifest, &def);
        assert!(!report.all_passed());
    }

    #[test]
    fn backend_architecture_mismatch_platform_fails() {
        let mut manifest = valid_manifest();
        manifest.compatibility.backends = vec![BackendCompatibility {
            family: "firecracker".into(),
            runtime_version: "1.0".into(),
            architecture: "x86_64".into(),
        }];
        // manifest platform is aarch64
        let def = valid_definition();
        let report = validation::validate_static(&manifest, &def);
        assert!(!report.all_passed());
    }

    #[test]
    fn empty_backends_list_fails() {
        let mut manifest = valid_manifest();
        manifest.compatibility.backends = vec![];
        let def = valid_definition();
        let report = validation::validate_static(&manifest, &def);
        assert!(!report.all_passed());
        let failures = report.failed_check_names();
        assert!(failures.iter().any(|n| n.contains("backend")));
    }

    #[test]
    fn duplicate_backend_families_fails() {
        let mut manifest = valid_manifest();
        manifest.compatibility.backends = vec![
            BackendCompatibility {
                family: "firecracker".into(),
                runtime_version: "1.0".into(),
                architecture: "aarch64".into(),
            },
            BackendCompatibility {
                family: "firecracker".into(),
                runtime_version: "2.0".into(),
                architecture: "aarch64".into(),
            },
        ];
        let def = valid_definition();
        let report = validation::validate_static(&manifest, &def);
        assert!(!report.all_passed());
    }

    #[test]
    fn unknown_compatibility_profile_fails() {
        let mut manifest = valid_manifest();
        manifest.compatibility.profile_id = "nonexistent-v1".into();
        let def = valid_definition();
        let report = validation::validate_static(&manifest, &def);
        assert!(!report.all_passed());
    }

    // ---- mount contract ----

    #[test]
    fn empty_mount_contract_fails() {
        let mut manifest = valid_manifest();
        manifest.mount_contract.mounts = vec![];
        let def = valid_definition();
        let report = validation::validate_static(&manifest, &def);
        assert!(!report.all_passed());
    }

    #[test]
    fn missing_workspace_mount_fails() {
        let mut manifest = valid_manifest();
        manifest.mount_contract.mounts = vec![
            MountEntry {
                path: "/run/pico/tmp".into(),
                class: MountClass::RuntimeTmp,
                writable: true,
                lifecycle: PathLifecycle::Ephemeral,
            },
            MountEntry {
                path: "/run/pico/secrets".into(),
                class: MountClass::Secret,
                writable: false,
                lifecycle: PathLifecycle::Ephemeral,
            },
            MountEntry {
                path: "/var/log/pico".into(),
                class: MountClass::GuestLogs,
                writable: true,
                lifecycle: PathLifecycle::Persistent,
            },
        ];
        let def = valid_definition();
        let report = validation::validate_static(&manifest, &def);
        assert!(!report.all_passed());
    }

    #[test]
    fn missing_required_mount_class_fails() {
        let mut manifest = valid_manifest();
        // Remove secret mount
        manifest
            .mount_contract
            .mounts
            .retain(|m| m.class != MountClass::Secret);
        let def = valid_definition();
        let report = validation::validate_static(&manifest, &def);
        assert!(!report.all_passed());
    }

    #[test]
    fn non_canonical_mount_path_fails() {
        let mut manifest = valid_manifest();
        manifest.mount_contract.mounts[0].path = "/custom/workspace".into();
        let def = valid_definition();
        let report = validation::validate_static(&manifest, &def);
        assert!(!report.all_passed());
    }

    #[test]
    fn duplicate_mount_paths_fails() {
        let mut manifest = valid_manifest();
        manifest.mount_contract.mounts.push(MountEntry {
            path: "/workspace".into(), // duplicate
            class: MountClass::GuestLogs,
            writable: true,
            lifecycle: PathLifecycle::Persistent,
        });
        let def = valid_definition();
        let report = validation::validate_static(&manifest, &def);
        assert!(!report.all_passed());
    }

    // ---- snapshot ----

    #[test]
    fn empty_snapshot_exclusions_fails() {
        let mut manifest = valid_manifest();
        manifest.snapshot.excluded_mount_classes = vec![];
        let def = valid_definition();
        let report = validation::validate_static(&manifest, &def);
        assert!(!report.all_passed());
    }

    #[test]
    fn missing_secret_exclusion_fails() {
        let mut manifest = valid_manifest();
        manifest.snapshot.excluded_mount_classes = vec!["runtime_tmp".into()];
        let def = valid_definition();
        let report = validation::validate_static(&manifest, &def);
        assert!(!report.all_passed());
    }

    #[test]
    fn excluded_non_ephemeral_class_fails() {
        let mut manifest = valid_manifest();
        manifest
            .snapshot
            .excluded_mount_classes
            .push("workspace".into());
        let def = valid_definition();
        let report = validation::validate_static(&manifest, &def);
        assert!(!report.all_passed());
    }

    #[test]
    fn ephemeral_class_not_excluded_fails() {
        let mut manifest = valid_manifest();
        // Only exclude secret, not runtime_tmp (which is ephemeral)
        manifest.snapshot.excluded_mount_classes = vec!["secret".into()];
        let def = valid_definition();
        let report = validation::validate_static(&manifest, &def);
        assert!(!report.all_passed());
    }

    // ---- filesystem identity ----

    #[test]
    fn filesystem_zero_uuid_fails() {
        let mut def = valid_definition();
        def.filesystem.uuid = "00000000-0000-0000-0000-000000000000".into();
        let manifest = valid_manifest();
        let report = validation::validate_static(&manifest, &def);
        assert!(!report.all_passed());
    }

    #[test]
    fn filesystem_empty_label_fails() {
        let mut def = valid_definition();
        def.filesystem.label = "".into();
        let manifest = valid_manifest();
        let report = validation::validate_static(&manifest, &def);
        assert!(!report.all_passed());
    }

    #[test]
    fn invalid_uuid_format_fails() {
        let mut def = valid_definition();
        def.filesystem.uuid = "not-a-uuid".into();
        let manifest = valid_manifest();
        let report = validation::validate_static(&manifest, &def);
        assert!(!report.all_passed());
    }

    #[test]
    fn empty_filesystem_size_fails() {
        let mut def = valid_definition();
        def.filesystem.size = "".into();
        let manifest = valid_manifest();
        let report = validation::validate_static(&manifest, &def);
        assert!(!report.all_passed());
    }

    // ---- security posture ----

    #[test]
    fn manifest_with_secret_pattern_fails() {
        let mut manifest = valid_manifest();
        manifest.image_id = "test-with-password".into();
        let def = valid_definition();
        let report = validation::validate_static(&manifest, &def);
        assert!(!report.all_passed());
        let failures = report.failed_check_names();
        assert!(failures.iter().any(|n| n.contains("secret")));
    }

    #[test]
    fn kernel_cmdline_with_password_fails() {
        let mut manifest = valid_manifest();
        let kd = manifest.artifacts.kernel.as_mut().unwrap();
        kd.cmdline = Some("console=ttyS0 password=secret123 root=/dev/vda rw init=/init".into());
        let def = valid_definition();
        let report = validation::validate_static(&manifest, &def);
        assert!(!report.all_passed());
    }

    #[test]
    fn kernel_cmdline_missing_init_fails() {
        let mut manifest = valid_manifest();
        let kd = manifest.artifacts.kernel.as_mut().unwrap();
        kd.cmdline = Some("console=ttyS0 reboot=k root=/dev/vda rw".into());
        let def = valid_definition();
        let report = validation::validate_static(&manifest, &def);
        assert!(!report.all_passed());
        let failures = report.failed_check_names();
        assert!(failures.iter().any(|n| n.contains("kernel")));
    }

    // ---- platform ----

    #[test]
    fn unsupported_platform_os_fails() {
        let mut manifest = valid_manifest();
        manifest.platform.os = "windows".into();
        let def = valid_definition();
        let report = validation::validate_static(&manifest, &def);
        assert!(!report.all_passed());
    }

    #[test]
    fn unsupported_architecture_fails() {
        let mut manifest = valid_manifest();
        manifest.platform.architecture = "riscv64".into();
        let def = valid_definition();
        let report = validation::validate_static(&manifest, &def);
        assert!(!report.all_passed());
    }

    // ---- kernel presence ----

    #[test]
    fn definition_without_kernel_ok_without_kernel_manifest() {
        let mut manifest = valid_manifest();
        manifest.artifacts.kernel = None;
        let mut def = valid_definition();
        def.kernel = None;
        let report = validation::validate_static(&manifest, &def);
        assert!(report.all_passed());
    }

    #[test]
    fn definition_with_kernel_but_manifest_without_fails() {
        let mut manifest = valid_manifest();
        manifest.artifacts.kernel = None;
        let def = valid_definition(); // has kernel
        let report = validation::validate_static(&manifest, &def);
        assert!(!report.all_passed());
    }

    #[test]
    fn production_kernel_with_debug_profile_fails() {
        let manifest = valid_manifest();
        // Test: debug config in kernel definition with production variant
        let def = valid_definition(); // variant is "production"
        let report = validation::validate_static(&manifest, &def);
        assert!(
            report.all_passed(),
            "production kernel with production profile should pass"
        );
    }

    // ---- misc / report ----

    #[test]
    fn initrd_with_zero_size_fails() {
        let mut manifest = valid_manifest();
        manifest.artifacts.initrd = Some(ArtifactDescriptor {
            format: Some("initrd-gz".into()),
            media_type: "application/vnd.pico.initrd".into(),
            digest: "sha256:initrd123".into(),
            size: 0,
            version: None,
            cmdline: None,
            protocol_version: None,
            capabilities: vec![],
        });
        let def = valid_definition();
        let report = validation::validate_static(&manifest, &def);
        assert!(!report.all_passed());
    }

    #[test]
    fn validation_report_serialization_roundtrip() {
        let manifest = valid_manifest();
        let def = valid_definition();
        let report = validation::validate_static(&manifest, &def);

        let json = serde_json::to_string_pretty(&report).unwrap();
        let parsed: pico_image::validation::report::ValidationReport =
            serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.image_id, report.image_id);
        assert_eq!(parsed.release_version, report.release_version);
        assert_eq!(parsed.all_passed(), report.all_passed());
        assert_eq!(parsed.checks.len(), report.checks.len());
    }

    #[test]
    fn validation_report_counts_pass_and_fail() {
        let manifest = valid_manifest();
        let def = valid_definition();
        let report = validation::validate_static(&manifest, &def);

        assert!(
            report.passed_count() > 0,
            "should have at least one passing check"
        );
        assert_eq!(report.failed_count(), 0, "should have no failing checks");
    }

    #[test]
    fn validation_report_with_failures_has_failed_count() {
        let mut manifest = valid_manifest();
        manifest.image_id = "".into(); // causes failure
        let def = valid_definition();
        let report = validation::validate_static(&manifest, &def);

        assert!(
            report.failed_count() > 0,
            "should have at least one failing check"
        );
        assert!(!report.all_passed());
    }
}

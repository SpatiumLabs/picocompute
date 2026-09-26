//! Negative validation fixture tests for.
//!
//! These tests cover the acceptance criteria:
//! - Missing guest-agent
//! - Bad manifest (various schema violations)
//! - Bad kernel config
//! - Unsigned production image (secret/credential presence)
//!
//! Each test constructs a deliberately invalid manifest or definition and
//! verifies that validation correctly rejects it with the expected error
//! category.

mod common;

#[cfg(test)]
mod negative_fixtures {
    use crate::common::{assert_validation_fails_with, valid_definition, valid_manifest};
    use pico_core::mount::MountClass;
    use pico_image::definition::*;
    use pico_image::types::*;
    use pico_image::validation;

    // -----------------------------------------------------------------------
    // NEGATIVE FIXTURE: Missing Guest-Agent
    // -----------------------------------------------------------------------

    #[test]
    fn missing_guest_agent_digest() {
        let mut manifest = valid_manifest();
        manifest.artifacts.guest_agent.digest = "".into();
        let def = valid_definition();
        assert_validation_fails_with(&manifest, &def, "guest-agent", "empty guest-agent digest");
    }

    #[test]
    fn missing_guest_agent_zero_size() {
        let mut manifest = valid_manifest();
        manifest.artifacts.guest_agent.size = 0;
        let def = valid_definition();
        assert_validation_fails_with(&manifest, &def, "guest-agent", "zero-size guest-agent");
    }

    #[test]
    fn missing_guest_agent_version() {
        let mut manifest = valid_manifest();
        manifest.artifacts.guest_agent.version = None;
        // Also remove version from definition to avoid the mismatch check
        let mut def = valid_definition();
        def.guest_agent = GuestAgentSource::Workspace {
            version: None,
            protocol_version: Some("1.0".into()),
            capabilities: vec!["exec".into()],
        };
        assert_validation_fails_with(
            &manifest,
            &def,
            "guest-agent",
            "missing guest-agent version",
        );
    }

    #[test]
    fn missing_guest_agent_protocol_version() {
        let mut manifest = valid_manifest();
        manifest.artifacts.guest_agent.protocol_version = None;
        let def = valid_definition();
        assert_validation_fails_with(&manifest, &def, "guest-agent", "missing protocol_version");
    }

    #[test]
    fn guest_agent_definition_without_version_causes_error() {
        let mut manifest = valid_manifest();
        manifest.artifacts.guest_agent.version = None;
        let mut def = valid_definition();
        def.guest_agent = GuestAgentSource::Workspace {
            version: None,
            protocol_version: Some("1.0".into()),
            capabilities: vec!["exec".into()],
        };
        let report = validation::validate_static(&manifest, &def);
        assert!(!report.all_passed());
    }

    // -----------------------------------------------------------------------
    // NEGATIVE FIXTURE: Bad Manifest
    // -----------------------------------------------------------------------

    #[test]
    fn bad_manifest_invalid_schema_version() {
        let mut manifest = valid_manifest();
        manifest.schema_version = "invalid".into();
        let def = valid_definition();
        assert_validation_fails_with(&manifest, &def, "schema", "invalid schema version");
    }

    #[test]
    fn bad_manifest_empty_image_id() {
        let mut manifest = valid_manifest();
        manifest.image_id = "".into();
        let def = valid_definition();
        assert_validation_fails_with(&manifest, &def, "image_id", "empty image_id");
    }

    #[test]
    fn bad_manifest_empty_rootfs_digest() {
        let mut manifest = valid_manifest();
        manifest.artifacts.rootfs.digest = "".into();
        let def = valid_definition();
        assert_validation_fails_with(&manifest, &def, "rootfs", "empty rootfs digest");
    }

    #[test]
    fn bad_manifest_rootfs_missing_format() {
        let mut manifest = valid_manifest();
        manifest.artifacts.rootfs.format = None;
        let def = valid_definition();
        assert_validation_fails_with(&manifest, &def, "rootfs", "missing rootfs format");
    }

    #[test]
    fn bad_manifest_digest_no_prefix() {
        let mut manifest = valid_manifest();
        manifest.artifacts.rootfs.digest = "bare-digest-with-no-prefix".into();
        let def = valid_definition();
        assert_validation_fails_with(&manifest, &def, "digest", "digest without sha256 prefix");
    }

    #[test]
    fn bad_manifest_duplicate_digests() {
        let mut manifest = valid_manifest();
        let dup = "sha256:dup123".to_string();
        manifest.artifacts.rootfs.digest = dup.clone();
        manifest.artifacts.guest_agent.digest = dup;
        let def = valid_definition();
        assert_validation_fails_with(&manifest, &def, "digest", "duplicate digests");
    }

    #[test]
    fn bad_manifest_empty_protocol_bootstrap() {
        let mut manifest = valid_manifest();
        manifest.protocol.bootstrap = "".into();
        let def = valid_definition();
        assert_validation_fails_with(&manifest, &def, "protocol", "empty bootstrap");
    }

    #[test]
    fn bad_manifest_empty_supported_protocols() {
        let mut manifest = valid_manifest();
        manifest.protocol.supported = vec![];
        let def = valid_definition();
        assert_validation_fails_with(&manifest, &def, "protocol", "empty supported versions");
    }

    #[test]
    fn bad_manifest_empty_backends() {
        let mut manifest = valid_manifest();
        manifest.compatibility.backends = vec![];
        let def = valid_definition();
        assert_validation_fails_with(&manifest, &def, "backend", "empty backends");
    }

    #[test]
    fn bad_manifest_unknown_backend() {
        let mut manifest = valid_manifest();
        manifest.compatibility.backends = vec![BackendCompatibility {
            family: "hypervisor-x".into(),
            runtime_version: "1.0".into(),
            architecture: "aarch64".into(),
        }];
        let def = valid_definition();
        assert_validation_fails_with(&manifest, &def, "backend", "unknown backend family");
    }

    #[test]
    fn bad_manifest_empty_mount_contract() {
        let mut manifest = valid_manifest();
        manifest.mount_contract.mounts = vec![];
        let def = valid_definition();
        assert_validation_fails_with(&manifest, &def, "mount", "empty mount contract");
    }

    #[test]
    fn bad_manifest_missing_mount_class() {
        let mut manifest = valid_manifest();
        // Remove workspace mount
        manifest
            .mount_contract
            .mounts
            .retain(|m| m.class != MountClass::Workspace);
        let def = valid_definition();
        assert_validation_fails_with(&manifest, &def, "mount", "missing workspace class");
    }

    #[test]
    fn bad_manifest_non_canonical_mount_path() {
        let mut manifest = valid_manifest();
        manifest.mount_contract.mounts[0].path = "/opt/workspace".into();
        let def = valid_definition();
        assert_validation_fails_with(&manifest, &def, "mount", "non-canonical path");
    }

    #[test]
    fn bad_manifest_empty_snapshot_exclusions() {
        let mut manifest = valid_manifest();
        manifest.snapshot.excluded_mount_classes = vec![];
        let def = valid_definition();
        assert_validation_fails_with(&manifest, &def, "snapshot", "empty snapshot exclusions");
    }

    #[test]
    fn bad_manifest_missing_secret_exclusion() {
        let mut manifest = valid_manifest();
        manifest.snapshot.excluded_mount_classes = vec!["runtime_tmp".into()];
        let def = valid_definition();
        assert_validation_fails_with(&manifest, &def, "snapshot", "missing secret exclusion");
    }

    #[test]
    fn bad_manifest_wrong_os() {
        let mut manifest = valid_manifest();
        manifest.platform.os = "darwin".into();
        let def = valid_definition();
        assert_validation_fails_with(&manifest, &def, "platform", "wrong OS");
    }

    #[test]
    fn bad_manifest_unknown_profile() {
        let mut manifest = valid_manifest();
        manifest.compatibility.profile_id = "nonexistent-v99".into();
        let def = valid_definition();
        assert_validation_fails_with(&manifest, &def, "backend", "unknown profile");
    }

    #[test]
    fn bad_manifest_protocol_capabilities_mismatch() {
        let mut manifest = valid_manifest();
        manifest.protocol.capabilities = vec!["exec".into(), "teleport".into()];
        let def = valid_definition();
        assert_validation_fails_with(&manifest, &def, "protocol", "capabilities mismatch");
    }

    // -----------------------------------------------------------------------
    // NEGATIVE FIXTURE: Bad Kernel Config
    // -----------------------------------------------------------------------

    #[test]
    fn bad_kernel_config_missing_init() {
        let mut manifest = valid_manifest();
        let kd = manifest.artifacts.kernel.as_mut().unwrap();
        kd.cmdline = Some("console=ttyS0 reboot=k root=/dev/vda rw".into());
        let def = valid_definition();
        assert_validation_fails_with(&manifest, &def, "kernel", "missing init=/init");
    }

    #[test]
    fn bad_kernel_config_missing_root() {
        let mut manifest = valid_manifest();
        let kd = manifest.artifacts.kernel.as_mut().unwrap();
        kd.cmdline = Some("console=ttyS0 reboot=k init=/init rw".into());
        let def = valid_definition();
        assert_validation_fails_with(&manifest, &def, "kernel", "missing root=/dev/vda");
    }

    #[test]
    fn bad_kernel_config_zero_size() {
        let mut manifest = valid_manifest();
        let kd = manifest.artifacts.kernel.as_mut().unwrap();
        kd.size = 0;
        let def = valid_definition();
        assert_validation_fails_with(&manifest, &def, "kernel", "kernel zero size");
    }

    #[test]
    fn bad_kernel_config_empty_digest() {
        let mut manifest = valid_manifest();
        let kd = manifest.artifacts.kernel.as_mut().unwrap();
        kd.digest = "".into();
        let def = valid_definition();
        assert_validation_fails_with(&manifest, &def, "kernel", "empty kernel digest");
    }

    #[test]
    fn bad_kernel_config_manifest_null() {
        let mut manifest = valid_manifest();
        manifest.artifacts.kernel = None;
        let def = valid_definition(); // has kernel
        assert_validation_fails_with(
            &manifest,
            &def,
            "kernel",
            "definition has kernel but manifest null",
        );
    }

    #[test]
    fn bad_kernel_config_definition_null() {
        let manifest = valid_manifest(); // has kernel
        let mut def = valid_definition();
        def.kernel = None;
        assert_validation_fails_with(
            &manifest,
            &def,
            "kernel",
            "manifest has kernel but definition null",
        );
    }

    #[test]
    fn bad_kernel_config_unknown_profile() {
        let mut def = valid_definition();
        def.kernel.as_mut().unwrap().config_profile = Some("imaginary-profile-v1".into());
        let manifest = valid_manifest();
        assert_validation_fails_with(&manifest, &def, "kernel", "unknown config profile");
    }

    #[test]
    fn bad_kernel_config_duplicate_with_rootfs_digest() {
        let mut manifest = valid_manifest();
        let dup = manifest.artifacts.rootfs.digest.clone();
        let kd = manifest.artifacts.kernel.as_mut().unwrap();
        kd.digest = dup;
        let def = valid_definition();
        assert_validation_fails_with(&manifest, &def, "digest", "kernel shares rootfs digest");
    }

    // -----------------------------------------------------------------------
    // NEGATIVE FIXTURE: Unsigned / Production Security (Secrets, Credentials)
    // -----------------------------------------------------------------------

    #[test]
    fn unsigned_production_password_in_manifest() {
        let mut manifest = valid_manifest();
        manifest.image_id = "image-with-password".into();
        let def = valid_definition();
        assert_validation_fails_with(&manifest, &def, "secret", "password pattern in manifest");
    }

    #[test]
    fn unsigned_production_kernel_cmdline_with_password() {
        let mut manifest = valid_manifest();
        let kd = manifest.artifacts.kernel.as_mut().unwrap();
        kd.cmdline = Some("console=ttyS0 root=/dev/vda rw init=/init password=secret123".into());
        let def = valid_definition();
        assert_validation_fails_with(&manifest, &def, "secret", "kernel cmdline with password");
    }

    #[test]
    fn unsigned_production_kernel_cmdline_with_token() {
        let mut manifest = valid_manifest();
        let kd = manifest.artifacts.kernel.as_mut().unwrap();
        kd.cmdline = Some("console=ttyS0 root=/dev/vda rw init=/init token=abc123".into());
        let def = valid_definition();
        assert_validation_fails_with(&manifest, &def, "secret", "kernel cmdline with token");
    }

    #[test]
    fn unsigned_production_kernel_cmdline_with_secret() {
        let mut manifest = valid_manifest();
        let kd = manifest.artifacts.kernel.as_mut().unwrap();
        kd.cmdline = Some("console=ttyS0 root=/dev/vda rw init=/init secret=xyz789".into());
        let def = valid_definition();
        assert_validation_fails_with(
            &manifest,
            &def,
            "secret",
            "kernel cmdline with secret param",
        );
    }

    #[test]
    fn unsigned_production_api_key_in_manifest_field() {
        let mut manifest = valid_manifest();
        // Use a field that ends up in JSON serialization
        manifest.image_id = "image-with-api_key-embedded".into();
        let def = valid_definition();
        assert_validation_fails_with(&manifest, &def, "secret", "api_key pattern in manifest");
    }

    /// Debug settings in production kernel cmdline.
    #[test]
    fn production_kernel_with_debug_cmdline() {
        let mut manifest = valid_manifest();
        let kd = manifest.artifacts.kernel.as_mut().unwrap();
        kd.cmdline = Some("console=ttyS0 debug root=/dev/vda rw init=/init".into());
        let def = valid_definition(); // variant is "production"
        assert_validation_fails_with(&manifest, &def, "kernel", "debug in production cmdline");
    }

    #[test]
    fn production_kernel_with_earlyprintk() {
        let mut manifest = valid_manifest();
        let kd = manifest.artifacts.kernel.as_mut().unwrap();
        kd.cmdline = Some("console=ttyS0 earlyprintk root=/dev/vda rw init=/init".into());
        let def = valid_definition(); // variant is "production"
        assert_validation_fails_with(&manifest, &def, "kernel", "earlyprintk in production");
    }

    #[test]
    fn production_kernel_with_slub_debug() {
        let mut manifest = valid_manifest();
        let kd = manifest.artifacts.kernel.as_mut().unwrap();
        kd.cmdline = Some("console=ttyS0 slub_debug root=/dev/vda rw init=/init".into());
        let def = valid_definition(); // variant is "production"
        assert_validation_fails_with(&manifest, &def, "kernel", "slub_debug in production");
    }

    // -----------------------------------------------------------------------
    // NEGATIVE FIXTURE: Filesystem Policy Violations
    // -----------------------------------------------------------------------

    #[test]
    fn bad_filesystem_zero_uuid() {
        let mut def = valid_definition();
        def.filesystem.uuid = "00000000-0000-0000-0000-000000000000".into();
        let manifest = valid_manifest();
        assert_validation_fails_with(&manifest, &def, "filesystem", "zero UUID");
    }

    #[test]
    fn bad_filesystem_empty_label() {
        let mut def = valid_definition();
        def.filesystem.label = "".into();
        let manifest = valid_manifest();
        assert_validation_fails_with(&manifest, &def, "filesystem", "empty label");
    }

    #[test]
    fn bad_filesystem_invalid_uuid() {
        let mut def = valid_definition();
        def.filesystem.uuid = "not-a-uuid".into();
        let manifest = valid_manifest();
        assert_validation_fails_with(&manifest, &def, "filesystem", "invalid UUID");
    }

    #[test]
    fn bad_filesystem_empty_size() {
        let mut def = valid_definition();
        def.filesystem.size = "".into();
        let manifest = valid_manifest();
        assert_validation_fails_with(&manifest, &def, "filesystem", "empty size");
    }

    // -----------------------------------------------------------------------
    // NEGATIVE FIXTURE: Backend Compatibility Violations
    // -----------------------------------------------------------------------

    #[test]
    fn architecture_mismatch_platform_vs_backend() {
        let mut manifest = valid_manifest();
        manifest.platform.architecture = "aarch64".into();
        // Backend says x86_64
        manifest.compatibility.backends = vec![BackendCompatibility {
            family: "firecracker".into(),
            runtime_version: "1.0".into(),
            architecture: "x86_64".into(),
        }];
        let def = valid_definition();
        assert_validation_fails_with(&manifest, &def, "backend", "architecture mismatch");
    }

    #[test]
    fn duplicate_backend_families() {
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
        assert_validation_fails_with(&manifest, &def, "backend", "duplicate backends");
    }

    #[test]
    fn guest_agent_version_mismatch() {
        let mut manifest = valid_manifest();
        manifest.artifacts.guest_agent.version = Some("9.9.9".into());
        let def = valid_definition(); // declares "0.3.0"
        assert_validation_fails_with(&manifest, &def, "guest-agent", "version mismatch");
    }

    #[test]
    fn guest_agent_protocol_version_mismatch() {
        let mut manifest = valid_manifest();
        manifest.artifacts.guest_agent.protocol_version = Some("2.0".into());
        let def = valid_definition(); // declares "1.0"
        assert_validation_fails_with(&manifest, &def, "guest-agent", "protocol_version mismatch");
    }

    // -----------------------------------------------------------------------
    // Combined / Edge-case negative scenarios
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_failures_all_reported() {
        let mut manifest = valid_manifest();
        manifest.image_id = "".into(); // fail 1
        manifest.artifacts.rootfs.digest = "".into(); // fail 2
        manifest.mount_contract.mounts = vec![]; // fail 3

        let def = valid_definition();
        let report = validation::validate_static(&manifest, &def);

        assert!(!report.all_passed());
        assert!(
            report.failed_count() >= 3,
            "expected at least 3 failures, got {}",
            report.failed_count()
        );

        let names = report.failed_check_names();
        assert!(names.iter().any(|n| n.contains("image_id")));
        assert!(names.iter().any(|n| n.contains("rootfs")));
        assert!(names.iter().any(|n| n.contains("mount")));
    }

    #[test]
    fn report_captures_failure_messages() {
        let mut manifest = valid_manifest();
        manifest.image_id = "".into();
        let def = valid_definition();
        let report = validation::validate_static(&manifest, &def);

        let failures = report.failed_checks();
        assert!(!failures.is_empty());

        for check in failures {
            match &check.outcome {
                pico_image::validation::report::CheckOutcome::Fail(msg) => {
                    assert!(!msg.is_empty(), "failure message should not be empty");
                }
                _ => panic!("expected Fail outcome"),
            }
        }
    }

    #[test]
    fn valid_fixture_passes_all() {
        let manifest = valid_manifest();
        let def = valid_definition();
        let report = validation::validate_static(&manifest, &def);
        assert!(report.all_passed(), "valid fixture should pass all checks");
        assert_eq!(report.failed_count(), 0);
    }
}

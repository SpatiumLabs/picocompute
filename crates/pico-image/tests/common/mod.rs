//! Shared test helpers for pico-image integration tests.
//!
//! Provides canonical "valid" manifest and definition fixtures used
//! across the negative fixture suite and static validation tests.

use pico_core::mount::{MountClass, MountEntry, PathLifecycle, SnapshotInfo};
use pico_image::definition::*;
use pico_image::types::*;

/// A fully valid guest manifest fixture (Firecracker aarch64 production).
pub(crate) fn valid_manifest() -> PicoComputeGuestManifest {
    PicoComputeGuestManifest {
        schema_version: "1.0".into(),
        image_id: "test-image".into(),
        release: ReleaseInfo {
            version: "0.1.0".into(),
            source_revision: "abc1234".into(),
            build_epoch: 1781170000,
        },
        platform: PlatformInfo {
            os: "linux".into(),
            architecture: "aarch64".into(),
        },
        artifacts: Artifacts {
            rootfs: ArtifactDescriptor {
                format: Some("ext4".into()),
                media_type: "application/vnd.pico.rootfs.ext4".into(),
                digest: "sha256:rootfs123".into(),
                size: 67108864,
                version: None,
                cmdline: None,
                protocol_version: None,
                capabilities: vec![],
            },
            kernel: Some(ArtifactDescriptor {
                format: Some("linux-vmlinux".into()),
                media_type: "application/vnd.pico.kernel.vmlinux".into(),
                digest: "sha256:kernel123".into(),
                size: 8388608,
                version: Some("pico-linux-6.18".into()),
                cmdline: Some(
                    "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw init=/init nomodules"
                        .into(),
                ),
                protocol_version: None,
                capabilities: vec![],
            }),
            initrd: None,
            firmware: None,
            guest_agent: ArtifactDescriptor {
                format: None,
                media_type: "application/vnd.pico.guest-agent".into(),
                digest: "sha256:agent123".into(),
                size: 5242880,
                version: Some("0.3.0".into()),
                cmdline: None,
                protocol_version: Some("1.0".into()),
                capabilities: vec!["exec".into()],
            },
        },
        protocol: ProtocolInfo {
            bootstrap: "pico.guest.bootstrap.v1".into(),
            supported: vec![ProtocolVersionRange {
                major: 1,
                min_minor: 0,
                max_minor: 0,
            }],
            capabilities: vec!["exec".into()],
        },
        compatibility: CompatibilityInfo {
            profile_id: "firecracker-aarch64-v1".into(),
            backends: vec![BackendCompatibility {
                family: "firecracker".into(),
                runtime_version: "1.0".into(),
                architecture: "aarch64".into(),
            }],
            required_cpu_features: vec![],
            required_devices: vec![],
            required_host_features: vec![],
            kernel_cmdline: None,
        },
        mount_contract: MountContract {
            version: "1.0".into(),
            mounts: vec![
                MountEntry {
                    path: "/workspace".into(),
                    class: MountClass::Workspace,
                    writable: true,
                    lifecycle: PathLifecycle::Persistent,
                },
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
            ],
        },
        snapshot: SnapshotInfo {
            filesystem: true,
            memory: false,
            excluded_mount_classes: vec!["runtime_tmp".into(), "secret".into()],
        },
    }
}

/// A fully valid image definition fixture (Firecracker aarch64 production).
pub(crate) fn valid_definition() -> ImageDefinition {
    ImageDefinition {
        image: ImageInfo {
            id: "test-image".into(),
            version: "0.1.0".into(),
            source_date_epoch: 1781170000,
        },
        base: BaseSource {
            source: SourceRef {
                url: "https://example.com/rootfs.tar.gz".into(),
                digest: "sha256:abc123".into(),
            },
        },
        packages: std::collections::BTreeMap::new(),
        guest_agent: GuestAgentSource::Workspace {
            version: Some("0.3.0".into()),
            protocol_version: Some("1.0".into()),
            capabilities: vec!["exec".into()],
        },
        filesystem: FilesystemConfig {
            size: "64M".into(),
            label: "test-root".into(),
            uuid: "11111111-1111-4111-a111-111111111111".into(),
        },
        mounts: vec![
            MountDef {
                path: "/workspace".into(),
                class: "workspace".into(),
                writable: true,
                lifecycle: PathLifecycle::Persistent,
            },
            MountDef {
                path: "/run/pico/tmp".into(),
                class: "runtime_tmp".into(),
                writable: true,
                lifecycle: PathLifecycle::Ephemeral,
            },
            MountDef {
                path: "/run/pico/secrets".into(),
                class: "secret".into(),
                writable: false,
                lifecycle: PathLifecycle::Ephemeral,
            },
            MountDef {
                path: "/var/log/pico".into(),
                class: "guest_logs".into(),
                writable: true,
                lifecycle: PathLifecycle::Persistent,
            },
        ],
        kernel: Some(KernelSource {
            backend: "firecracker".into(),
            variant: "production".into(),
            version: "pico-linux-6.18".into(),
            cmdline: Some(
                "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw init=/init nomodules"
                    .into(),
            ),
            vmlinux_path: None,
            initrd_path: None,
            firmware_path: None,
            config_profile: Some("firecracker-aarch64-v1".into()),
        }),
    }
}

/// Helper: run validation and assert it fails with the expected check name.
#[allow(dead_code)]
pub(crate) fn assert_validation_fails_with(
    manifest: &PicoComputeGuestManifest,
    definition: &ImageDefinition,
    expected_check_contains: &str,
    context: &str,
) {
    let report = pico_image::validation::validate_static(manifest, definition);
    assert!(
        !report.all_passed(),
        "{}: expected validation to fail, but it passed",
        context
    );
    let failures = report.failed_check_names();
    let found = failures.iter().any(|n| n.contains(expected_check_contains));
    assert!(
        found,
        "{}: expected failure for '{}', but failed checks were: {:?}",
        context, expected_check_contains, failures
    );
}

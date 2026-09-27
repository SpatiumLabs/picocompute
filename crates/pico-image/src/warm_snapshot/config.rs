//! Warm snapshot generation configuration.
//!
//! Controls per-image-profile warm snapshot behaviour: whether it is
//! enabled, what timeout to apply for guest-agent readiness, and whether
//! restore validation is required before promotion.

use crate::types::PicoComputeGuestManifest;
use camino::Utf8PathBuf;
use pico_core::snapshot::shape::{BackendRecord, CpuShape, DeviceModel, MemoryShape};

/// Per-image-profile configuration for warm snapshot generation.
///
/// Maps to the `[warm_snapshot]` section of an image definition.
/// When `enabled` is `true`, the image pipeline will attempt to produce
/// a warm base snapshot after the rootfs image is built.
#[derive(Debug, Clone)]
pub struct WarmSnapshotConfig {
    /// Whether warm snapshot generation is enabled for this image profile.
    /// Default: `false`.
    pub enabled: bool,

    /// Timeout in seconds for guest-agent readiness before capture.
    /// Must be at least 1. Default: 30.
    pub readiness_timeout_secs: u64,

    /// Whether restore validation is required before image promotion.
    /// When `true`, the pipeline blocks promotion if restore validation
    /// fails or is skipped.
    /// Default: `true`.
    pub require_restore_validation: bool,

    /// Maximum acceptable restore latency in milliseconds.
    /// If restore exceeds this, the snapshot is rejected.
    /// Default: 5000 (5 seconds).
    pub max_restore_latency_ms: u64,

    /// Directory where warm snapshot artifacts and metadata are written.
    pub output_dir: Utf8PathBuf,

    /// The image manifest that the snapshot is derived from.
    pub image_manifest: PicoComputeGuestManifest,

    /// Backend information for compatibility tagging.
    pub backend: BackendRecord,

    /// CPU shape for compatibility tagging.
    pub cpu_shape: CpuShape,

    /// Memory shape for compatibility tagging.
    pub memory_shape: MemoryShape,

    /// Device model for compatibility tagging.
    pub device_model: DeviceModel,
}

impl WarmSnapshotConfig {
    /// Minimum allowed readiness timeout in seconds.
    pub const MIN_READINESS_TIMEOUT_SECS: u64 = 1;

    /// Default readiness timeout in seconds.
    pub const DEFAULT_READINESS_TIMEOUT_SECS: u64 = 30;

    /// Default maximum restore latency in milliseconds.
    pub const DEFAULT_MAX_RESTORE_LATENCY_MS: u64 = 5000;

    /// Creates a new configuration with defaults.
    pub fn new(
        enabled: bool,
        output_dir: impl Into<Utf8PathBuf>,
        image_manifest: PicoComputeGuestManifest,
    ) -> Self {
        let backend_family = image_manifest
            .compatibility
            .backends
            .first()
            .map(|b| b.family.as_str())
            .unwrap_or("firecracker");

        let architecture = image_manifest.platform.architecture.clone();

        let backend = BackendRecord {
            backend_type: backend_family.into(),
            backend_version: image_manifest
                .compatibility
                .backends
                .first()
                .map(|b| b.runtime_version.clone())
                .unwrap_or_else(|| "1.0".into()),
            protocol_version: image_manifest
                .protocol
                .supported
                .first()
                .map(|r| format!("{}.{}", r.major, r.min_minor))
                .unwrap_or_else(|| "1.0".into()),
            guest_agent_version: image_manifest.artifacts.guest_agent.version.clone(),
        };

        Self {
            enabled,
            readiness_timeout_secs: Self::DEFAULT_READINESS_TIMEOUT_SECS,
            require_restore_validation: true,
            max_restore_latency_ms: Self::DEFAULT_MAX_RESTORE_LATENCY_MS,
            output_dir: output_dir.into(),
            image_manifest,
            backend,
            cpu_shape: CpuShape::new(architecture),
            memory_shape: MemoryShape {
                memory_mb: 2048,
                vcpus: 2,
            },
            device_model: DeviceModel::new("q35"),
        }
    }

    /// Validates the configuration and returns an error if required fields
    /// are missing or invalid.
    pub fn validate(&self) -> Result<(), String> {
        if self.readiness_timeout_secs < Self::MIN_READINESS_TIMEOUT_SECS {
            return Err(format!(
                "readiness_timeout_secs must be at least {} (got {})",
                Self::MIN_READINESS_TIMEOUT_SECS,
                self.readiness_timeout_secs
            ));
        }

        if self.image_manifest.image_id.is_empty() {
            return Err("image_manifest.image_id is empty".into());
        }

        if self.image_manifest.artifacts.rootfs.digest.is_empty() {
            return Err("image_manifest.artifacts.rootfs.digest is empty".into());
        }

        if self.image_manifest.artifacts.guest_agent.digest.is_empty() {
            return Err("image_manifest.artifacts.guest_agent.digest is empty".into());
        }

        if self.image_manifest.artifacts.guest_agent.version.is_none() {
            return Err(
                "image_manifest.artifacts.guest_agent.version is missing; required for warm snapshot compatibility"
                    .into(),
            );
        }

        if self.backend.guest_agent_version.is_none() {
            return Err("backend.guest_agent_version is missing".into());
        }

        Ok(())
    }

    /// Returns true if warm snapshot is required by this profile.
    ///
    /// A profile requires warm snapshot when `enabled` is `true`.
    pub fn is_required(&self) -> bool {
        self.enabled
    }

    /// Returns the image ID from the manifest.
    pub fn image_id(&self) -> &str {
        &self.image_manifest.image_id
    }

    /// Returns the root filesystem digest from the manifest.
    pub fn rootfs_digest(&self) -> &str {
        &self.image_manifest.artifacts.rootfs.digest
    }

    /// Returns the kernel version from the manifest, if available.
    pub fn kernel_version(&self) -> Option<&str> {
        self.image_manifest
            .artifacts
            .kernel
            .as_ref()
            .and_then(|k| k.version.as_deref())
    }

    /// Returns the guest-agent version from the manifest.
    pub fn guest_agent_version(&self) -> &str {
        self.image_manifest
            .artifacts
            .guest_agent
            .version
            .as_deref()
            .unwrap_or("unknown")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        ArtifactDescriptor, Artifacts, CompatibilityInfo, PlatformInfo, ProtocolInfo,
        ProtocolVersionRange, ReleaseInfo, SnapshotInfo,
    };
    use pico_core::mount::{MountClass, MountContract, MountEntry, PathLifecycle};

    fn make_test_manifest() -> PicoComputeGuestManifest {
        PicoComputeGuestManifest {
            schema_version: "1.0".into(),
            image_id: "test-image-001".into(),
            release: ReleaseInfo {
                version: "1.0.0".into(),
                source_revision: "abc123".into(),
                build_epoch: 1700000000,
            },
            platform: PlatformInfo {
                os: "linux".into(),
                architecture: "x86_64".into(),
            },
            artifacts: Artifacts {
                rootfs: ArtifactDescriptor {
                    format: Some("ext4".into()),
                    media_type: "application/vnd.pico.rootfs.ext4".into(),
                    digest: "sha256:rootfs123".into(),
                    size: 1024000,
                    version: None,
                    cmdline: None,
                    protocol_version: None,
                    capabilities: vec![],
                },
                kernel: Some(ArtifactDescriptor {
                    format: Some("linux-vmlinux".into()),
                    media_type: "application/vnd.pico.kernel.vmlinux".into(),
                    digest: "sha256:kernel123".into(),
                    size: 8192000,
                    version: Some("6.1.0".into()),
                    cmdline: Some("console=ttyS0".into()),
                    protocol_version: None,
                    capabilities: vec![],
                }),
                initrd: None,
                firmware: None,
                guest_agent: ArtifactDescriptor {
                    format: None,
                    media_type: "application/vnd.pico.guest-agent".into(),
                    digest: "sha256:agent123".into(),
                    size: 4096000,
                    version: Some("0.5.0".into()),
                    cmdline: None,
                    protocol_version: Some("1.0".into()),
                    capabilities: vec!["exec".into(), "snapshot".into()],
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
                profile_id: "firecracker-x86_64-v1".into(),
                backends: vec![crate::types::BackendCompatibility {
                    family: "firecracker".into(),
                    runtime_version: "1.10.0".into(),
                    architecture: "x86_64".into(),
                }],
                required_cpu_features: vec![],
                required_devices: vec![],
                required_host_features: vec![],
                kernel_cmdline: Some("console=ttyS0".into()),
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
                        path: "/run/pico/secrets".into(),
                        class: MountClass::Secret,
                        writable: false,
                        lifecycle: PathLifecycle::Ephemeral,
                    },
                ],
            },
            snapshot: SnapshotInfo {
                filesystem: true,
                memory: false,
                excluded_mount_classes: vec!["secret".into()],
            },
            environment: None,
        }
    }

    #[test]
    fn config_validation_passes_with_valid_manifest() {
        let manifest = make_test_manifest();
        let config = WarmSnapshotConfig::new(true, "/tmp/warm-snapshot", manifest);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn config_validation_fails_with_empty_image_id() {
        let mut manifest = make_test_manifest();
        manifest.image_id = String::new();
        let config = WarmSnapshotConfig::new(true, "/tmp/warm-snapshot", manifest);
        assert!(config.validate().is_err());
    }

    #[test]
    fn config_validation_fails_with_empty_rootfs_digest() {
        let mut manifest = make_test_manifest();
        manifest.artifacts.rootfs.digest = String::new();
        let config = WarmSnapshotConfig::new(true, "/tmp/warm-snapshot", manifest);
        assert!(config.validate().is_err());
    }

    #[test]
    fn config_validation_fails_with_timeout_below_minimum() {
        let manifest = make_test_manifest();
        let mut config = WarmSnapshotConfig::new(true, "/tmp/warm-snapshot", manifest);
        config.readiness_timeout_secs = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn config_is_required_when_enabled() {
        let manifest = make_test_manifest();
        let config = WarmSnapshotConfig::new(true, "/tmp/warm-snapshot", manifest);
        assert!(config.is_required());
    }

    #[test]
    fn config_is_not_required_when_disabled() {
        let manifest = make_test_manifest();
        let config = WarmSnapshotConfig::new(false, "/tmp/warm-snapshot", manifest);
        assert!(!config.is_required());
    }

    #[test]
    fn config_kernel_version_from_manifest() {
        let manifest = make_test_manifest();
        let config = WarmSnapshotConfig::new(true, "/tmp/warm-snapshot", manifest);
        assert_eq!(config.kernel_version(), Some("6.1.0"));
    }

    #[test]
    fn config_kernel_version_none_when_no_kernel() {
        let mut manifest = make_test_manifest();
        manifest.artifacts.kernel = None;
        let config = WarmSnapshotConfig::new(true, "/tmp/warm-snapshot", manifest);
        assert_eq!(config.kernel_version(), None);
    }

    #[test]
    fn config_guest_agent_version_from_manifest() {
        let manifest = make_test_manifest();
        let config = WarmSnapshotConfig::new(true, "/tmp/warm-snapshot", manifest);
        assert_eq!(config.guest_agent_version(), "0.5.0");
    }

    #[test]
    fn config_rootfs_digest_from_manifest() {
        let manifest = make_test_manifest();
        let config = WarmSnapshotConfig::new(true, "/tmp/warm-snapshot", manifest);
        assert_eq!(config.rootfs_digest(), "sha256:rootfs123");
    }

    #[test]
    fn config_image_id_from_manifest() {
        let manifest = make_test_manifest();
        let config = WarmSnapshotConfig::new(true, "/tmp/warm-snapshot", manifest);
        assert_eq!(config.image_id(), "test-image-001");
    }

    #[test]
    fn config_default_values() {
        let manifest = make_test_manifest();
        let config = WarmSnapshotConfig::new(true, "/tmp/warm-snapshot", manifest);
        assert_eq!(
            config.readiness_timeout_secs,
            WarmSnapshotConfig::DEFAULT_READINESS_TIMEOUT_SECS
        );
        assert!(config.require_restore_validation);
        assert_eq!(
            config.max_restore_latency_ms,
            WarmSnapshotConfig::DEFAULT_MAX_RESTORE_LATENCY_MS
        );
    }
}

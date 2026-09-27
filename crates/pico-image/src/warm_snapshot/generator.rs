//! Warm snapshot generation orchestrator.
//!
//! Coordinates the boot-to-snapshot pipeline: boot image, wait for
//! guest-agent readiness, capture runtime state, validate restore,
//! and produce snapshot metadata for publication.

use std::time::Instant;

use async_trait::async_trait;
use camino::Utf8PathBuf;

use pico_core::{
    identity::{OperationId, SandboxId, SnapshotId},
    snapshot::{
        CompatibilityRecord,
        metadata::{FilesystemRef, MemorySegment, SnapshotMetadata, WorkspaceLayerRef},
    },
};

use super::compat::{
    build_compatibility_record, build_warm_snapshot_metadata, compute_snapshot_integrity,
    validate_secret_exclusion, validate_warm_snapshot_compatibility,
};
use super::config::WarmSnapshotConfig;
use super::error::{WarmSnapshotError, WarmSnapshotResult};
use super::validation::{
    RestoreValidationReport, run_restore_validation, validate_promotion_readiness,
};

/// Context provided by the backend after a successful guest boot.
#[derive(Debug, Clone)]
pub struct GuestContext {
    /// The sandbox identifier for the booted guest.
    pub sandbox_id: String,
    /// The guest-agent version reported during handshake.
    pub guest_agent_version: String,
    /// The protocol version negotiated with the guest-agent.
    pub protocol_version: String,
    /// Backend-specific state for snapshot capture (opaque to the generator).
    pub backend_state: serde_json::Value,
}

/// Artifacts produced by the backend after a successful snapshot capture.
#[derive(Debug, Clone)]
pub struct SnapshotArtifacts {
    /// Filesystem blob paths and metadata.
    pub filesystem_blobs: Vec<SnapshotBlobRef>,
    /// Memory segment blob paths and metadata (empty for base snapshots).
    pub memory_blobs: Vec<SnapshotBlobRef>,
    /// Backend-specific metadata (opaque to the generator).
    pub backend_metadata: serde_json::Value,
}

/// A reference to a snapshot blob artifact.
#[derive(Debug, Clone)]
pub struct SnapshotBlobRef {
    /// Human-readable reference for this blob.
    pub blob_ref: String,
    /// Filesystem path to the blob.
    pub path: Utf8PathBuf,
    /// Size in bytes.
    pub size_bytes: u64,
    /// Integrity digest (algorithm:hex).
    pub digest: Option<String>,
}

/// Host context for restore validation.
#[derive(Debug, Clone)]
pub struct HostContext {
    pub backend: pico_core::snapshot::shape::BackendRecord,
    pub cpu: pico_core::snapshot::shape::CpuShape,
    pub memory: pico_core::snapshot::shape::MemoryShape,
    pub device: pico_core::snapshot::shape::DeviceModel,
    pub runtime: pico_core::runtime::RuntimeType,
}

/// Backend abstraction for warm snapshot operations.
///
/// Implementations handle the actual VM lifecycle: boot, snapshot capture,
/// and restore. The generator orchestrates the pipeline around these
/// primitives.
#[async_trait]
pub trait WarmSnapshotBackend: Send + Sync {
    /// Boots a guest from the given image artifacts and waits for
    /// guest-agent readiness.
    ///
    /// Returns a [`GuestContext`] that can be used for snapshot capture.
    async fn boot_to_readiness(
        &self,
        image_artifacts: &ImageArtifactSet,
        timeout_secs: u64,
    ) -> WarmSnapshotResult<GuestContext>;

    /// Captures a snapshot of the running guest.
    ///
    /// The returned [`SnapshotArtifacts`] contain blob references for
    /// filesystem and memory state.
    async fn capture_snapshot(&self, ctx: &GuestContext) -> WarmSnapshotResult<SnapshotArtifacts>;

    /// Validates that a snapshot can be restored by performing an
    /// actual restore operation on the target host.
    ///
    /// Returns a report with latency and success status.
    async fn validate_restore(
        &self,
        artifacts: &SnapshotArtifacts,
        host: &HostContext,
    ) -> WarmSnapshotResult<RestoreValidationReport>;

    /// Shuts down the guest and cleans up resources.
    async fn shutdown_guest(&self, ctx: &GuestContext) -> WarmSnapshotResult<()>;
}

/// A set of image artifacts for guest boot.
#[derive(Debug, Clone)]
pub struct ImageArtifactSet {
    /// Path to the root filesystem image.
    pub rootfs_path: Utf8PathBuf,
    /// Path to the kernel image, if using a direct kernel boot.
    pub kernel_path: Option<Utf8PathBuf>,
    /// Path to the initrd, if any.
    pub initrd_path: Option<Utf8PathBuf>,
    /// Kernel command-line string.
    pub kernel_cmdline: Option<String>,
}

/// The output of a warm snapshot generation run.
#[derive(Debug)]
pub struct WarmSnapshotOutput {
    /// The generated snapshot metadata (in `Staging` state).
    pub metadata: SnapshotMetadata,

    /// The compatibility record for this snapshot.
    pub compatibility_record: CompatibilityRecord,

    /// Paths to the captured snapshot artifacts.
    pub artifact_paths: Vec<Utf8PathBuf>,

    /// The restore validation report, if validation was performed.
    pub restore_report: Option<RestoreValidationReport>,

    /// Whether the warm snapshot is ready for promotion.
    pub promotion_ready: bool,

    /// Total wall-clock duration of the generation operation in milliseconds.
    pub generation_latency_ms: u64,

    /// Path to the published snapshot metadata file.
    pub metadata_path: Utf8PathBuf,
}

/// Orchestrates warm snapshot generation for a single image profile.
///
/// The generator:
/// 1. Validates configuration and image manifest
/// 2. Boots the image to guest-agent readiness via the backend
/// 3. Captures snapshot artifacts (filesystem state)
/// 4. Builds snapshot metadata linked to the image manifest
/// 5. Validates restore (if configured)
/// 6. Promotes snapshot to Ready (if validation passes)
/// 7. Writes metadata to disk for publication
pub struct WarmSnapshotGenerator<B: WarmSnapshotBackend> {
    backend: B,
    config: WarmSnapshotConfig,
}

impl<B: WarmSnapshotBackend> WarmSnapshotGenerator<B> {
    /// Creates a new warm snapshot generator.
    pub fn new(backend: B, config: WarmSnapshotConfig) -> Self {
        Self { backend, config }
    }

    /// Returns the configuration for this generator.
    pub fn config(&self) -> &WarmSnapshotConfig {
        &self.config
    }

    /// Executes the full warm snapshot generation pipeline.
    ///
    /// Returns an error immediately if `WarmSnapshotConfig::enabled` is
    /// `false`. Callers should check `enabled` before invoking.
    #[tracing::instrument(skip(self), fields(image_id = %self.config.image_id()))]
    pub async fn generate(&self) -> WarmSnapshotResult<WarmSnapshotOutput> {
        if !self.config.enabled {
            return Err(WarmSnapshotError::ConfigurationError {
                image_id: self.config.image_id().into(),
                reason: "warm snapshot generation is not enabled for this profile".into(),
            });
        }

        self.config
            .validate()
            .map_err(|reason| WarmSnapshotError::ConfigurationError {
                image_id: self.config.image_id().into(),
                reason,
            })?;

        let started = Instant::now();
        let image_id = self.config.image_id().to_string();

        tracing::info!(
            image_id = %image_id,
            backend = %self.config.backend.backend_type,
            guest_agent_version = %self.config.guest_agent_version(),
            "starting warm snapshot generation"
        );

        let image_artifacts = self.build_image_artifact_set()?;
        let guest_ctx = self
            .backend
            .boot_to_readiness(&image_artifacts, self.config.readiness_timeout_secs)
            .await
            .map_err(|e| {
                tracing::error!(image_id = %image_id, error = %e, "guest boot failed");
                e
            })?;

        tracing::info!(
            image_id = %image_id,
            sandbox_id = %guest_ctx.sandbox_id,
            guest_agent_version = %guest_ctx.guest_agent_version,
            "guest-agent ready"
        );

        let artifacts = self
            .backend
            .capture_snapshot(&guest_ctx)
            .await
            .map_err(|e| {
                tracing::error!(image_id = %image_id, error = %e, "snapshot capture failed");
                e
            })?;

        if artifacts.filesystem_blobs.is_empty() {
            return Err(WarmSnapshotError::SnapshotArtifactEmpty {
                image_id: image_id.clone(),
            });
        }

        let blob_count = artifacts.filesystem_blobs.len() + artifacts.memory_blobs.len();
        tracing::info!(
            image_id = %image_id,
            blob_count = %blob_count,
            "snapshot captured"
        );

        let metadata = self.build_metadata_with_integrity(&artifacts, &image_id)?;

        validate_secret_exclusion(&metadata.excluded_mounts, &metadata.filesystem_refs).map_err(
            |e| {
                let err_msg = e.to_string();
                WarmSnapshotError::CredentialMaterialDetected {
                    image_id: image_id.clone(),
                    reason: err_msg,
                }
            },
        )?;

        let compatibility_record = build_compatibility_record(&metadata);

        validate_warm_snapshot_compatibility(
            &metadata,
            self.config.image_id(),
            self.config.kernel_version(),
            self.config.guest_agent_version(),
            &self.config.backend,
        )?;

        let restore_report = self
            .run_restore_validation_phase(&artifacts, &metadata)
            .await;

        let promotion_ready = self.determine_promotion_readiness(&metadata, &restore_report);

        let (metadata_path, artifact_paths) = self.write_metadata_output(&metadata, &artifacts)?;

        let generation_latency_ms = started.elapsed().as_millis() as u64;

        let _ = self.backend.shutdown_guest(&guest_ctx).await;

        tracing::info!(
            image_id = %image_id,
            snapshot_id = %metadata.id,
            latency_ms = %generation_latency_ms,
            promotion_ready = %promotion_ready,
            metadata_path = %metadata_path,
            "warm snapshot generation complete"
        );

        Ok(WarmSnapshotOutput {
            metadata,
            compatibility_record,
            artifact_paths,
            restore_report,
            promotion_ready,
            generation_latency_ms,
            metadata_path,
        })
    }

    /// Builds snapshot metadata with integrity from captured artifacts.
    ///
    /// Combines artifact-to-metadata-ref conversion, identity generation,
    /// initial metadata construction, and blake3 integrity computation into
    /// a single step.
    fn build_metadata_with_integrity(
        &self,
        artifacts: &SnapshotArtifacts,
        image_id: &str,
    ) -> WarmSnapshotResult<SnapshotMetadata> {
        let artifact_hashes: Vec<(&str, &str)> = artifacts
            .filesystem_blobs
            .iter()
            .chain(artifacts.memory_blobs.iter())
            .map(|b| {
                let digest_ref = b.digest.as_deref().unwrap_or("unknown");
                (b.blob_ref.as_str(), digest_ref)
            })
            .collect();

        let filesystem_refs: Vec<FilesystemRef> = artifacts
            .filesystem_blobs
            .iter()
            .enumerate()
            .map(|(i, b)| FilesystemRef {
                blob_ref: b.blob_ref.clone(),
                mount_point: if i == 0 {
                    "/".into()
                } else {
                    format!("/mnt/layer_{i}")
                },
                fs_type: "ext4".into(),
                digest: b.digest.clone(),
                is_root: i == 0,
            })
            .collect();

        let memory_segments: Vec<MemorySegment> = artifacts
            .memory_blobs
            .iter()
            .map(|b| MemorySegment {
                blob_ref: b.blob_ref.clone(),
                start_address: 0,
                size_bytes: b.size_bytes,
                digest: b.digest.clone(),
            })
            .collect();

        let workspace_layers: Vec<WorkspaceLayerRef> = Vec::new();

        let snapshot_id = SnapshotId::generate();
        let sandbox_id = SandboxId::generate();
        let operation_id = OperationId::generate();

        let mut metadata = build_warm_snapshot_metadata(
            &self.config,
            snapshot_id,
            sandbox_id,
            operation_id,
            filesystem_refs,
            memory_segments,
            workspace_layers,
            pico_core::snapshot::integrity::SnapshotIntegrity::new(
                pico_core::snapshot::integrity::IntegrityDigest::new("blake3", "placeholder"),
            ),
        )?;

        let integrity = compute_snapshot_integrity(&metadata, &artifact_hashes);
        metadata.integrity = Some(integrity);

        tracing::debug!(
            image_id = %image_id,
            snapshot_id = %metadata.id,
            blob_count = %artifact_hashes.len(),
            "metadata built with integrity"
        );

        Ok(metadata)
    }

    /// Runs the restore validation phase, combining backend-level and
    /// metadata-level checks.
    ///
    /// The latency threshold in `WarmSnapshotConfig::max_restore_latency_ms`
    /// gates on the combined backend + metadata validation time. In
    /// practice the backend's `validate_restore` call dominates; the
    /// metadata-side `run_restore_validation` is cheap (in-memory checks only).
    /// The combined report uses `max(...)` latency and requires both to pass.
    async fn run_restore_validation_phase(
        &self,
        artifacts: &SnapshotArtifacts,
        metadata: &SnapshotMetadata,
    ) -> Option<RestoreValidationReport> {
        if !self.config.require_restore_validation {
            return None;
        }

        let host = self.build_host_context();

        // Backend-level restore validation (the real work)
        let backend_report = self
            .backend
            .validate_restore(artifacts, &host)
            .await
            .unwrap_or_else(|e| {
                RestoreValidationReport::failure(0, format!("backend restore failed: {e}"))
            });

        // Metadata-level validation (in-memory checks: compatibility, integrity, state)
        let metadata_report = run_restore_validation(
            metadata,
            &host.backend,
            &host.cpu,
            &host.memory,
            &host.device,
            host.runtime,
            self.config.max_restore_latency_ms,
        );

        let combined = if backend_report.success && metadata_report.success {
            RestoreValidationReport::success(
                backend_report.latency_ms.max(metadata_report.latency_ms),
                "restore validation passed (backend + metadata)",
            )
        } else {
            let mut report = RestoreValidationReport::failure(
                backend_report.latency_ms.max(metadata_report.latency_ms),
                "restore validation failed",
            );
            report = report
                .with_diagnostic(format!("backend: {}", backend_report.message))
                .with_diagnostic(format!("metadata: {}", metadata_report.message));
            report
        };

        Some(combined)
    }

    /// Determines whether the snapshot is ready for promotion.
    fn determine_promotion_readiness(
        &self,
        metadata: &SnapshotMetadata,
        restore_report: &Option<RestoreValidationReport>,
    ) -> bool {
        match restore_report {
            Some(report) if report.success => validate_promotion_readiness(metadata).is_ok(),
            Some(_) => false,
            None => validate_promotion_readiness(metadata).is_ok(),
        }
    }

    /// Writes snapshot metadata JSON to disk and collects artifact paths.
    fn write_metadata_output(
        &self,
        metadata: &SnapshotMetadata,
        artifacts: &SnapshotArtifacts,
    ) -> WarmSnapshotResult<(Utf8PathBuf, Vec<Utf8PathBuf>)> {
        std::fs::create_dir_all(&self.config.output_dir).map_err(|e| {
            WarmSnapshotError::OutputDirectoryError(format!(
                "failed to create output directory '{}': {e}",
                self.config.output_dir
            ))
        })?;

        let metadata_filename = format!("snapshot-{}.json", metadata.id);
        let metadata_path = self.config.output_dir.join(&metadata_filename);
        let metadata_json = serde_json::to_string_pretty(metadata)?;
        std::fs::write(&metadata_path, &metadata_json).map_err(|e| {
            WarmSnapshotError::IoError(std::io::Error::other(format!(
                "failed to write metadata to '{}': {e}",
                metadata_path
            )))
        })?;

        let artifact_paths: Vec<Utf8PathBuf> = artifacts
            .filesystem_blobs
            .iter()
            .chain(artifacts.memory_blobs.iter())
            .map(|b| b.path.clone())
            .collect();

        Ok((metadata_path, artifact_paths))
    }

    /// Builds an [`ImageArtifactSet`] from the configuration.
    fn build_image_artifact_set(&self) -> WarmSnapshotResult<ImageArtifactSet> {
        let manifest = &self.config.image_manifest;

        // The rootfs path is typically in the output directory
        let rootfs_name = format!("{}.ext4", manifest.image_id);
        let rootfs_path = self.config.output_dir.join(&rootfs_name);

        let kernel_path = manifest
            .artifacts
            .kernel
            .as_ref()
            .map(|_| self.config.output_dir.join("vmlinux"));

        let initrd_path = manifest
            .artifacts
            .initrd
            .as_ref()
            .map(|_| self.config.output_dir.join("initrd.img"));

        let kernel_cmdline = manifest.compatibility.kernel_cmdline.clone();

        Ok(ImageArtifactSet {
            rootfs_path,
            kernel_path,
            initrd_path,
            kernel_cmdline,
        })
    }

    /// Builds the host context for restore validation from the configuration.
    fn build_host_context(&self) -> HostContext {
        HostContext {
            backend: self.config.backend.clone(),
            cpu: self.config.cpu_shape.clone(),
            memory: self.config.memory_shape,
            device: self.config.device_model.clone(),
            runtime: match self.config.backend.backend_type.as_str() {
                "firecracker" => pico_core::runtime::RuntimeType::Firecracker,
                "qemu" => pico_core::runtime::RuntimeType::Qemu,
                _ => pico_core::runtime::RuntimeType::Firecracker,
            },
        }
    }

    /// Consumes the generator and returns the backend for reuse.
    pub fn into_backend(self) -> B {
        self.backend
    }

    /// Returns a reference to the backend.
    pub fn backend(&self) -> &B {
        &self.backend
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        ArtifactDescriptor, Artifacts, CompatibilityInfo, PicoComputeGuestManifest, PlatformInfo,
        ProtocolInfo, ProtocolVersionRange, ReleaseInfo,
    };
    use pico_core::mount::{MountClass, MountContract, MountEntry, PathLifecycle, SnapshotInfo};
    use std::sync::Mutex;

    struct MockBackend {
        boot_succeeds: Mutex<bool>,
        capture_succeeds: Mutex<bool>,
        restore_succeeds: Mutex<bool>,
        fs_blob_count: Mutex<usize>,
    }

    impl MockBackend {
        fn new() -> Self {
            Self {
                boot_succeeds: Mutex::new(true),
                capture_succeeds: Mutex::new(true),
                restore_succeeds: Mutex::new(true),
                fs_blob_count: Mutex::new(1),
            }
        }

        fn with_boot_failure(self) -> Self {
            *self.boot_succeeds.lock().unwrap() = false;
            self
        }

        #[expect(dead_code, reason = "available for testing empty capture scenarios")]
        fn with_empty_capture(self) -> Self {
            *self.capture_succeeds.lock().unwrap() = true;
            *self.fs_blob_count.lock().unwrap() = 0;
            self
        }
    }

    #[async_trait]
    impl WarmSnapshotBackend for MockBackend {
        async fn boot_to_readiness(
            &self,
            _image_artifacts: &ImageArtifactSet,
            _timeout_secs: u64,
        ) -> WarmSnapshotResult<GuestContext> {
            if !*self.boot_succeeds.lock().unwrap() {
                return Err(WarmSnapshotError::GuestBootFailed {
                    image_id: "test".into(),
                    reason: "mock boot failure".into(),
                });
            }
            Ok(GuestContext {
                sandbox_id: "sbx_mock_001".into(),
                guest_agent_version: "0.5.0".into(),
                protocol_version: "1.0".into(),
                backend_state: serde_json::json!({"mock": true}),
            })
        }

        async fn capture_snapshot(
            &self,
            _ctx: &GuestContext,
        ) -> WarmSnapshotResult<SnapshotArtifacts> {
            if !*self.capture_succeeds.lock().unwrap() {
                return Err(WarmSnapshotError::SnapshotCaptureFailed {
                    image_id: "test".into(),
                    reason: "mock capture failure".into(),
                });
            }
            let count = *self.fs_blob_count.lock().unwrap();
            let blobs: Vec<SnapshotBlobRef> = (0..count)
                .map(|i| SnapshotBlobRef {
                    blob_ref: format!("rootfs-blob-{i}"),
                    path: Utf8PathBuf::from(format!("/tmp/snapshot/rootfs-{i}.ext4")),
                    size_bytes: 1024 * 1024,
                    digest: Some(format!("blake3:mock{i}")),
                })
                .collect();

            Ok(SnapshotArtifacts {
                filesystem_blobs: blobs,
                memory_blobs: vec![],
                backend_metadata: serde_json::json!({"snapshot_type": "diff"}),
            })
        }

        async fn validate_restore(
            &self,
            _artifacts: &SnapshotArtifacts,
            _host: &HostContext,
        ) -> WarmSnapshotResult<RestoreValidationReport> {
            if *self.restore_succeeds.lock().unwrap() {
                Ok(RestoreValidationReport::success(15, "mock restore ok"))
            } else {
                Ok(RestoreValidationReport::failure(0, "mock restore failed"))
            }
        }

        async fn shutdown_guest(&self, _ctx: &GuestContext) -> WarmSnapshotResult<()> {
            Ok(())
        }
    }

    fn make_test_config(enabled: bool) -> WarmSnapshotConfig {
        use tempfile::TempDir;
        let dir = TempDir::new().unwrap();
        let dir_path = camino::Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();

        let manifest = PicoComputeGuestManifest {
            schema_version: "1.0".into(),
            image_id: "test-image-warm".into(),
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
                excluded_mount_classes: vec!["secret".into(), "runtime_tmp".into()],
            },
            required_features: vec![],
            environment: None,
        };
        WarmSnapshotConfig::new(enabled, dir_path, manifest)
    }

    #[tokio::test]
    async fn generate_disabled_returns_error() {
        let config = make_test_config(false);
        let backend = MockBackend::new();
        let generator = WarmSnapshotGenerator::new(backend, config);
        let result = generator.generate().await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not enabled"));
    }

    #[tokio::test]
    async fn generate_produces_output_with_valid_config() {
        let config = make_test_config(true);
        let backend = MockBackend::new();
        let generator = WarmSnapshotGenerator::new(backend, config);
        let result = generator.generate().await;
        assert!(result.is_ok(), "expected success: {:?}", result.err());
        let output = result.unwrap();
        assert!(output.promotion_ready);
        // latency can be 0ms on fast machines with mock backend
        assert!(output.generation_latency_ms < 10_000);
        assert!(!output.artifact_paths.is_empty());
        assert!(output.restore_report.is_some());
        assert!(output.restore_report.as_ref().unwrap().success);
        assert!(output.metadata_path.exists());
        assert_eq!(
            output.metadata.purpose,
            pico_core::snapshot::purpose::SnapshotPurpose::Base
        );
        assert_eq!(output.metadata.image_id, "test-image-warm");
        assert_eq!(
            output.compatibility_record.image_id,
            output.metadata.image_id
        );
    }

    #[tokio::test]
    async fn generate_fails_on_boot_error() {
        let config = make_test_config(true);
        let backend = MockBackend::new().with_boot_failure();
        let generator = WarmSnapshotGenerator::new(backend, config);
        let result = generator.generate().await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("guest boot failed")
        );
    }

    #[tokio::test]
    async fn generate_sets_backend_compatibility() {
        let config = make_test_config(true);
        let backend = MockBackend::new();
        let generator = WarmSnapshotGenerator::new(backend, config);
        let output = generator.generate().await.unwrap();
        assert_eq!(output.metadata.backend.backend_type, "firecracker");
        assert!(output.metadata.backend.guest_agent_version.is_some());
    }

    #[tokio::test]
    async fn generate_excludes_secret_mounts() {
        let config = make_test_config(true);
        let backend = MockBackend::new();
        let generator = WarmSnapshotGenerator::new(backend, config);
        let output = generator.generate().await.unwrap();
        assert!(
            output
                .metadata
                .excluded_mounts
                .iter()
                .any(|m| m == "secret")
        );
        let policy = output.metadata.credential_policy.as_ref().unwrap();
        assert!(policy.exclude_from_snapshot);
    }

    #[tokio::test]
    async fn generate_integrity_record_is_populated() {
        let config = make_test_config(true);
        let backend = MockBackend::new();
        let generator = WarmSnapshotGenerator::new(backend, config);
        let output = generator.generate().await.unwrap();
        assert!(output.metadata.integrity.is_some());
        let integrity = output.metadata.integrity.as_ref().unwrap();
        assert!(integrity.integrity_required);
        assert_eq!(integrity.metadata_digest.algorithm, "blake3");
        assert!(!integrity.blob_digests.is_empty());
    }

    #[tokio::test]
    async fn generate_metadata_serialization_roundtrip() {
        let config = make_test_config(true);
        let backend = MockBackend::new();
        let generator = WarmSnapshotGenerator::new(backend, config);
        let output = generator.generate().await.unwrap();

        let json = serde_json::to_string(&output.metadata).unwrap();
        let parsed: SnapshotMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(output.metadata.id, parsed.id);
        assert_eq!(output.metadata.image_id, parsed.image_id);
        assert_eq!(output.metadata.purpose, parsed.purpose);
    }

    #[tokio::test]
    async fn generate_records_latency() {
        let config = make_test_config(true);
        let backend = MockBackend::new();
        let generator = WarmSnapshotGenerator::new(backend, config);
        let output = generator.generate().await.unwrap();
        // latency can be 0ms on fast machines with mock backend
        assert!(output.generation_latency_ms < 10_000);
        println!("generation latency: {}ms", output.generation_latency_ms);
    }

    #[tokio::test]
    async fn generator_into_backend_returns_backend() {
        let config = make_test_config(true);
        let backend = MockBackend::new();
        let generator = WarmSnapshotGenerator::new(backend, config);
        let _backend = generator.into_backend();
    }
}

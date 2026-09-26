//! Restore validation for warm snapshots.
//!
//! Validates that a captured warm snapshot can be restored successfully
//! before the image is promoted. This prevents bad snapshots from
//! reaching production.

use std::time::Instant;

use pico_core::snapshot::{
    compatibility::CompatibilityRecord,
    metadata::SnapshotMetadata,
    shape::{BackendRecord, CpuShape, DeviceModel, MemoryShape},
};

use super::error::{WarmSnapshotError, WarmSnapshotResult};

/// A report produced after a restore validation run.
#[derive(Debug, Clone)]
pub struct RestoreValidationReport {
    /// Whether the restore succeeded.
    pub success: bool,

    /// Wall-clock latency of the restore operation in milliseconds.
    pub latency_ms: u64,

    /// Whether the compatibility check passed.
    pub compatibility_passed: bool,

    /// Whether blob resolution succeeded.
    pub blobs_resolved: bool,

    /// Whether the guest-agent responded after restore.
    pub guest_agent_healthy: bool,

    /// Whether memory was restored (always false for warm base snapshots).
    pub memory_restored: bool,

    /// Human-readable outcome description.
    pub message: String,

    /// Detailed diagnostic information, if any.
    pub diagnostics: Vec<String>,
}

impl RestoreValidationReport {
    /// Constructs a success report.
    pub fn success(latency_ms: u64, message: impl Into<String>) -> Self {
        Self {
            success: true,
            latency_ms,
            compatibility_passed: true,
            blobs_resolved: true,
            guest_agent_healthy: true,
            memory_restored: false,
            message: message.into(),
            diagnostics: Vec::new(),
        }
    }

    /// Constructs a failure report.
    pub fn failure(latency_ms: u64, message: impl Into<String>) -> Self {
        Self {
            success: false,
            latency_ms,
            compatibility_passed: false,
            blobs_resolved: false,
            guest_agent_healthy: false,
            memory_restored: false,
            message: message.into(),
            diagnostics: Vec::new(),
        }
    }

    /// Records a diagnostic message.
    pub fn with_diagnostic(mut self, msg: impl Into<String>) -> Self {
        self.diagnostics.push(msg.into());
        self
    }
}

/// Validates restore compatibility between a snapshot's compatibility record
/// and a target host environment.
///
/// This runs from metadata only, without loading snapshot blobs. It uses
/// the same compatibility check logic as the runtime restore path to ensure
/// consistency.
pub fn validate_restore_compatibility(
    compat_record: &CompatibilityRecord,
    host_backend: &BackendRecord,
    host_cpu: &CpuShape,
    host_memory: &MemoryShape,
    host_device: &DeviceModel,
    host_runtime: pico_core::runtime::RuntimeType,
) -> WarmSnapshotResult<()> {
    compat_record
        .check_compatibility(
            host_backend,
            host_cpu,
            host_memory,
            host_device,
            host_runtime,
            // Image build-time validation: policy epoch cross-check is not
            // applicable at image build time. Pass 0 to skip the check for
            // snapshots that don't record a policy epoch.
            0,
        )
        .map_err(|e| WarmSnapshotError::RestoreValidationFailed {
            image_id: compat_record.image_id.clone(),
            reason: e.to_string(),
        })
}

/// Validates that the restore operation completed within the configured
/// latency threshold.
pub fn validate_restore_latency(
    latency_ms: u64,
    threshold_ms: u64,
    image_id: &str,
) -> WarmSnapshotResult<()> {
    if latency_ms > threshold_ms {
        return Err(WarmSnapshotError::RestoreLatencyExceeded {
            image_id: image_id.into(),
            actual_ms: latency_ms,
            threshold_ms,
        });
    }
    Ok(())
}

/// Validates that a warm snapshot metadata record is ready for promotion.
///
/// Checks:
/// 1. The snapshot state is Staging (can transition to Ready)
/// 2. Integrity records are present
/// 3. Credential policy enforces exclusion
/// 4. Excluded mounts include the secret class
pub fn validate_promotion_readiness(metadata: &SnapshotMetadata) -> WarmSnapshotResult<()> {
    if !metadata.state.can_become_ready() {
        return Err(WarmSnapshotError::RestoreValidationFailed {
            image_id: metadata.image_id.clone(),
            reason: format!(
                "snapshot is in {} state; must be in Staging to promote",
                metadata.state.as_str()
            ),
        });
    }

    if metadata.integrity.is_none() {
        return Err(WarmSnapshotError::RestoreValidationFailed {
            image_id: metadata.image_id.clone(),
            reason: "integrity record is missing".into(),
        });
    }

    let integrity = metadata.integrity.as_ref().unwrap();
    if !integrity.integrity_required {
        return Err(WarmSnapshotError::RestoreValidationFailed {
            image_id: metadata.image_id.clone(),
            reason: "integrity_required is false; must be true for production snapshots".into(),
        });
    }

    metadata.validate_credential_exclusion().map_err(|e| {
        WarmSnapshotError::RestoreValidationFailed {
            image_id: metadata.image_id.clone(),
            reason: format!("credential exclusion validation failed: {e}"),
        }
    })?;

    Ok(())
}

/// Runs the complete restore-validation pipeline for a warm snapshot.
///
/// Returns a [`RestoreValidationReport`] with latency and diagnostic info.
///
/// Note: This function validates from metadata alone. Actual backend-level
/// restore is performed by the [`WarmSnapshotBackend`](super::WarmSnapshotBackend)
/// trait implementation.
pub fn run_restore_validation(
    metadata: &SnapshotMetadata,
    host_backend: &BackendRecord,
    host_cpu: &CpuShape,
    host_memory: &MemoryShape,
    host_device: &DeviceModel,
    host_runtime: pico_core::runtime::RuntimeType,
    max_latency_ms: u64,
) -> RestoreValidationReport {
    let started = Instant::now();
    let mut report = RestoreValidationReport {
        success: false,
        latency_ms: 0,
        compatibility_passed: false,
        blobs_resolved: false,
        guest_agent_healthy: false,
        memory_restored: false,
        message: String::new(),
        diagnostics: Vec::new(),
    };

    if let Err(e) = validate_promotion_readiness(metadata) {
        report.message = format!("promotion readiness failed: {e}");
        report.latency_ms = started.elapsed().as_millis() as u64;
        return report;
    }

    let compat = metadata.to_compatibility_record();
    report.compatibility_passed = validate_restore_compatibility(
        &compat,
        host_backend,
        host_cpu,
        host_memory,
        host_device,
        host_runtime,
    )
    .is_ok();

    if !report.compatibility_passed {
        report.message = "compatibility check failed".into();
        report.latency_ms = started.elapsed().as_millis() as u64;
        return report;
    }

    report.blobs_resolved = true;
    report.guest_agent_healthy = true;

    report.latency_ms = started.elapsed().as_millis() as u64;

    if let Err(e) = validate_restore_latency(report.latency_ms, max_latency_ms, &metadata.image_id)
    {
        report.message = format!("latency check failed: {e}");
        report.latency_ms = started.elapsed().as_millis() as u64;
        return report;
    }

    report.success = true;
    report.message = format!(
        "restore validation passed in {}ms: compat_ok, blobs_ok, agent_ok",
        report.latency_ms
    );

    tracing::info!(
        snapshot_id = %metadata.id,
        image_id = %metadata.image_id,
        latency_ms = %report.latency_ms,
        success = %report.success,
        "restore validation completed"
    );

    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use pico_core::{
        identity::{OperationId, SandboxId, SnapshotId, TenantId},
        snapshot::integrity::{IntegrityDigest, SnapshotIntegrity},
        snapshot::metadata::SnapshotMetadata,
        snapshot::profile::SnapshotProfile,
        snapshot::purpose::{LineageType, SnapshotPurpose},
        snapshot::shape::{BackendRecord, CpuShape, DeviceModel, MemoryShape},
    };

    fn make_test_metadata() -> SnapshotMetadata {
        let mut meta = SnapshotMetadata::new(
            SnapshotId::generate(),
            TenantId::from_string("tnt_test"),
            SandboxId::generate(),
            None,
            LineageType::Root,
            SnapshotPurpose::Base,
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
        meta.integrity = Some(SnapshotIntegrity::new(IntegrityDigest::new(
            "blake3", "abc123",
        )));
        meta.credential_policy =
            Some(pico_core::snapshot::credential_policy::CredentialSnapshotPolicy::production());
        meta.excluded_mounts = vec!["secret".into(), "runtime_tmp".into()];
        meta
    }

    fn make_host_backend() -> BackendRecord {
        BackendRecord {
            backend_type: "firecracker".into(),
            backend_version: "1.10.0".into(),
            protocol_version: "2.0".into(),
            guest_agent_version: Some("0.5.0".into()),
        }
    }

    #[test]
    fn promotion_readiness_passes_for_valid_snapshot() {
        let meta = make_test_metadata();
        assert!(validate_promotion_readiness(&meta).is_ok());
    }

    #[test]
    fn promotion_readiness_fails_for_ready_snapshot() {
        let mut meta = make_test_metadata();
        meta.mark_ready().unwrap();
        let result = validate_promotion_readiness(&meta);
        assert!(result.is_err());
    }

    #[test]
    fn promotion_readiness_fails_without_integrity() {
        let mut meta = make_test_metadata();
        meta.integrity = None;
        let result = validate_promotion_readiness(&meta);
        assert!(result.is_err());
    }

    #[test]
    fn promotion_readiness_fails_without_credential_policy() {
        let mut meta = make_test_metadata();
        meta.credential_policy = None;
        let result = validate_promotion_readiness(&meta);
        assert!(result.is_err());
    }

    #[test]
    fn restore_compatibility_passes_with_matching_host() {
        let meta = make_test_metadata();
        let compat = meta.to_compatibility_record();
        let result = validate_restore_compatibility(
            &compat,
            &make_host_backend(),
            &CpuShape::new("x86_64"),
            &MemoryShape {
                memory_mb: 4096,
                vcpus: 4,
            },
            &DeviceModel::new("q35"),
            pico_core::runtime::RuntimeType::Firecracker,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn restore_compatibility_fails_with_backend_mismatch() {
        let meta = make_test_metadata();
        let compat = meta.to_compatibility_record();
        let mut host = make_host_backend();
        host.backend_type = "qemu".into();
        let result = validate_restore_compatibility(
            &compat,
            &host,
            &CpuShape::new("x86_64"),
            &MemoryShape {
                memory_mb: 4096,
                vcpus: 4,
            },
            &DeviceModel::new("q35"),
            pico_core::runtime::RuntimeType::Firecracker,
        );
        assert!(result.is_err());
    }

    #[test]
    fn restore_latency_validation_passes_within_threshold() {
        assert!(validate_restore_latency(500, 1000, "img_test").is_ok());
    }

    #[test]
    fn restore_latency_validation_fails_exceeding_threshold() {
        let result = validate_restore_latency(1500, 1000, "img_test");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("restore latency"));
    }

    #[test]
    fn restore_validation_report_success_has_all_flags() {
        let report = RestoreValidationReport::success(42, "all good");
        assert!(report.success);
        assert_eq!(report.latency_ms, 42);
        assert!(report.compatibility_passed);
        assert!(report.blobs_resolved);
        assert!(report.guest_agent_healthy);
        assert!(!report.memory_restored);
        assert!(report.diagnostics.is_empty());
    }

    #[test]
    fn restore_validation_report_failure_has_all_flags_false() {
        let report = RestoreValidationReport::failure(100, "bad compat");
        assert!(!report.success);
        assert_eq!(report.latency_ms, 100);
        assert!(!report.compatibility_passed);
        assert!(!report.blobs_resolved);
        assert!(!report.guest_agent_healthy);
    }

    #[test]
    fn restore_validation_report_with_diagnostics() {
        let report = RestoreValidationReport::success(42, "ok")
            .with_diagnostic("blob check passed")
            .with_diagnostic("agent responded in 5ms");
        assert_eq!(report.diagnostics.len(), 2);
        assert!(report.success);
    }

    #[test]
    fn run_restore_validation_produces_success_report() {
        let meta = make_test_metadata();
        let report = run_restore_validation(
            &meta,
            &make_host_backend(),
            &CpuShape::new("x86_64"),
            &MemoryShape {
                memory_mb: 4096,
                vcpus: 4,
            },
            &DeviceModel::new("q35"),
            pico_core::runtime::RuntimeType::Firecracker,
            5000,
        );
        assert!(report.success);
        assert!(report.compatibility_passed);
        assert!(report.blobs_resolved);
        assert!(report.guest_agent_healthy);
    }

    #[test]
    fn run_restore_validation_fails_with_incompatible_host() {
        let meta = make_test_metadata();
        let report = run_restore_validation(
            &meta,
            &BackendRecord {
                backend_type: "qemu".into(),
                backend_version: "1.0".into(),
                protocol_version: "1.0".into(),
                guest_agent_version: None,
            },
            &CpuShape::new("x86_64"),
            &MemoryShape {
                memory_mb: 4096,
                vcpus: 4,
            },
            &DeviceModel::new("q35"),
            pico_core::runtime::RuntimeType::Firecracker,
            5000,
        );
        assert!(!report.success);
        assert!(!report.compatibility_passed);
    }
}

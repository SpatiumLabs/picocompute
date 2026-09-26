//! Typed warm-snapshot generation and restore-validation errors.
//!
//! Each variant captures a specific failure mode in the
//! boot-to-snapshot, capture, metadata publication, or restore-validation
//! pipeline. Production callers should map these to structured telemetry.

use thiserror::Error;

/// Errors specific to warm snapshot generation operations.
#[derive(Debug, Error)]
pub enum WarmSnapshotError {
    /// The image manifest is missing required artifact descriptors
    /// (e.g., rootfs digest, guest-agent version).
    #[error("warm snapshot manifest validation failed: {0}")]
    ManifestValidationFailed(String),

    /// The backend failed to boot the image to guest-agent readiness.
    #[error("guest boot failed for image '{image_id}': {reason}")]
    GuestBootFailed {
        /// Image identifier that failed to boot.
        image_id: String,
        /// Human-readable reason.
        reason: String,
    },

    /// The guest-agent did not become ready within the configured timeout.
    #[error("guest-agent readiness timeout for image '{image_id}' after {timeout_secs}s: {reason}")]
    GuestAgentReadyTimeout {
        /// Image identifier.
        image_id: String,
        /// Timeout duration in seconds.
        timeout_secs: u64,
        /// Reason (e.g., last observed state).
        reason: String,
    },

    /// The guest-agent handshake or protocol negotiation failed.
    #[error("guest-agent handshake failed for image '{image_id}': {reason}")]
    GuestAgentHandshakeFailed {
        /// Image identifier.
        image_id: String,
        /// Human-readable reason.
        reason: String,
    },

    /// Snapshot capture failed at the backend level.
    #[error("snapshot capture failed for image '{image_id}': {reason}")]
    SnapshotCaptureFailed {
        /// Image identifier.
        image_id: String,
        /// Human-readable reason.
        reason: String,
    },

    /// The generated snapshot artifact is empty or missing required blobs.
    #[error("snapshot artifact empty or incomplete for image '{image_id}'")]
    SnapshotArtifactEmpty {
        /// Image identifier.
        image_id: String,
    },

    /// A required blob reference in the snapshot metadata could not be found.
    #[error("snapshot blob missing: '{blob_ref}'")]
    SnapshotBlobMissing {
        /// Blob reference that was expected but not found.
        blob_ref: String,
    },

    /// Restore validation failed, meaning the snapshot is not usable.
    #[error("restore validation failed for image '{image_id}': {reason}")]
    RestoreValidationFailed {
        /// Image identifier.
        image_id: String,
        /// Human-readable reason.
        reason: String,
    },

    /// Compatibility check failed between the snapshot and target host.
    #[error("snapshot compatibility check failed: {reason}")]
    CompatibilityCheckFailed {
        /// Human-readable incompatibility reason.
        reason: String,
    },

    /// The snapshot cannot be promoted because warm snapshot generation was
    /// required by the profile but the generation step failed or was skipped.
    #[error(
        "warm snapshot required by profile for image '{image_id}' but generation did not produce a valid artifact"
    )]
    WarmSnapshotRequired {
        /// Image identifier.
        image_id: String,
    },

    /// Secret or tenant data was detected in the snapshot artifact.
    #[error("credential material detected in warm snapshot for image '{image_id}': {reason}")]
    CredentialMaterialDetected {
        /// Image identifier.
        image_id: String,
        /// Description of the detected material.
        reason: String,
    },

    /// A filesystem or I/O error occurred during snapshot generation.
    #[error("warm snapshot I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// A JSON serialization or deserialization error occurred.
    #[error("warm snapshot serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    /// An error propagated from the pico-core snapshot layer.
    #[error("snapshot metadata error: {0}")]
    SnapshotMetadataError(String),

    /// The output directory does not exist or is not writable.
    #[error("output directory error: {0}")]
    OutputDirectoryError(String),

    /// Image definition or manifest is missing required warm-snapshot fields.
    #[error("warm snapshot configuration error for image '{image_id}': {reason}")]
    ConfigurationError {
        /// Image identifier.
        image_id: String,
        /// Human-readable reason.
        reason: String,
    },

    /// Backend does not support warm snapshot generation.
    #[error("backend '{backend_type}' does not support warm snapshot generation")]
    UnsupportedBackend {
        /// Backend family name.
        backend_type: String,
    },

    /// Restore latency exceeded the configured threshold.
    #[error(
        "restore latency {actual_ms}ms exceeded threshold {threshold_ms}ms for image '{image_id}'"
    )]
    RestoreLatencyExceeded {
        /// Image identifier.
        image_id: String,
        /// Measured latency in milliseconds.
        actual_ms: u64,
        /// Configured threshold in milliseconds.
        threshold_ms: u64,
    },
}

/// Convenience alias for warm snapshot results.
pub type WarmSnapshotResult<T> = std::result::Result<T, WarmSnapshotError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_boot_failed_display() {
        let err = WarmSnapshotError::GuestBootFailed {
            image_id: "img_test".into(),
            reason: "kernel panic".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("guest boot failed"));
        assert!(msg.contains("img_test"));
        assert!(msg.contains("kernel panic"));
    }

    #[test]
    fn guest_agent_ready_timeout_display() {
        let err = WarmSnapshotError::GuestAgentReadyTimeout {
            image_id: "img_test".into(),
            timeout_secs: 30,
            reason: "vsock not connected".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("readiness timeout"));
        assert!(msg.contains("30s"));
    }

    #[test]
    fn credential_material_detected_display() {
        let err = WarmSnapshotError::CredentialMaterialDetected {
            image_id: "img_test".into(),
            reason: "secret mount path found in filesystem ref".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("credential material detected"));
        assert!(msg.contains("img_test"));
    }

    #[test]
    fn restore_latency_exceeded_display() {
        let err = WarmSnapshotError::RestoreLatencyExceeded {
            image_id: "img_test".into(),
            actual_ms: 1500,
            threshold_ms: 1000,
        };
        let msg = err.to_string();
        assert!(msg.contains("1500"));
        assert!(msg.contains("1000"));
    }

    #[test]
    fn io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let warm_err: WarmSnapshotError = io_err.into();
        assert!(matches!(warm_err, WarmSnapshotError::IoError(_)));
    }

    #[test]
    fn all_error_variants_display_meaningful() {
        let errors = [
            WarmSnapshotError::ManifestValidationFailed("missing rootfs".into()),
            WarmSnapshotError::GuestBootFailed {
                image_id: "img".into(),
                reason: "panic".into(),
            },
            WarmSnapshotError::GuestAgentReadyTimeout {
                image_id: "img".into(),
                timeout_secs: 30,
                reason: "timeout".into(),
            },
            WarmSnapshotError::GuestAgentHandshakeFailed {
                image_id: "img".into(),
                reason: "proto mismatch".into(),
            },
            WarmSnapshotError::SnapshotCaptureFailed {
                image_id: "img".into(),
                reason: "backend error".into(),
            },
            WarmSnapshotError::SnapshotArtifactEmpty {
                image_id: "img".into(),
            },
            WarmSnapshotError::SnapshotBlobMissing {
                blob_ref: "mem.bin".into(),
            },
            WarmSnapshotError::RestoreValidationFailed {
                image_id: "img".into(),
                reason: "checksum mismatch".into(),
            },
            WarmSnapshotError::CompatibilityCheckFailed {
                reason: "cpu arch mismatch".into(),
            },
            WarmSnapshotError::WarmSnapshotRequired {
                image_id: "img".into(),
            },
            WarmSnapshotError::CredentialMaterialDetected {
                image_id: "img".into(),
                reason: "secret leak".into(),
            },
            WarmSnapshotError::SnapshotMetadataError("invalid state".into()),
            WarmSnapshotError::OutputDirectoryError("not writable".into()),
            WarmSnapshotError::ConfigurationError {
                image_id: "img".into(),
                reason: "no guest agent version".into(),
            },
            WarmSnapshotError::UnsupportedBackend {
                backend_type: "qemu".into(),
            },
            WarmSnapshotError::RestoreLatencyExceeded {
                image_id: "img".into(),
                actual_ms: 5000,
                threshold_ms: 2000,
            },
        ];
        for err in &errors {
            let msg = err.to_string();
            assert!(
                !msg.is_empty(),
                "error variant should produce a non-empty message"
            );
        }
    }
}

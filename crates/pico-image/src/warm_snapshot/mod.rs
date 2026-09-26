//! Warm snapshot generation for the PicoCompute guest image pipeline.
//!
//! Implements: Warm Snapshot Generation.
//!
//! This module provides the build-time workflow for producing warm base
//! snapshots from validated guest images. The pipeline:
//!
//! 1. Boots an image to guest-agent readiness
//! 2. Captures reusable base runtime state
//! 3. Publishes snapshot metadata linked to image manifest
//! 4. Validates restore before image promotion
//! 5. Tags compatibility by backend, kernel, guest-agent, and image version
//! 6. Excludes secret and tenant paths from snapshot artifacts
//!
//! # Architecture
//!
//! The [`WarmSnapshotGenerator`] orchestrates the pipeline around a
//! [`WarmSnapshotBackend`] trait that abstracts the actual VM lifecycle
//! operations. This separation allows different backends (Firecracker,
//! QEMU, etc.) to be plugged in without changing the pipeline logic.
//!
//! Snapshot metadata follows the model defined in and is
//! compatible with the restore coordinator from.
//!
//! # Implementing a Backend
//!
//! To add support for a new VM backend (e.g., cloud-hypervisor, gVisor),
//! implement the [`WarmSnapshotBackend`] trait. The generator handles
//! metadata, compatibility, integrity, and secret-exclusion; the backend
//! only needs to manage the VM lifecycle.
//!
//! ```rust,no_run
//! # use async_trait::async_trait;
//! # use pico_image::warm_snapshot::{
//! #     GuestContext, ImageArtifactSet, RestoreValidationReport, SnapshotArtifacts,
//! #     WarmSnapshotBackend, WarmSnapshotError, WarmSnapshotResult,
//! # };
//! struct MyBackend;
//!
//! #[async_trait]
//! impl WarmSnapshotBackend for MyBackend {
//!     async fn boot_to_readiness(
//!         &self,
//!         artifacts: &ImageArtifactSet,
//!         timeout_secs: u64,
//!     ) -> WarmSnapshotResult<GuestContext> {
//!         // 1. Launch VM with rootfs + kernel from artifacts
//!         // 2. Connect to guest-agent over vsock
//!         // 3. Poll / wait for ready handshake
//!         // 4. Return GuestContext with sandbox_id and version info
//!         todo!("implement VM boot for your backend")
//!     }
//!
//!     async fn capture_snapshot(
//!         &self,
//!         ctx: &GuestContext,
//!     ) -> WarmSnapshotResult<SnapshotArtifacts> {
//!         // 1. Trigger snapshot via backend API
//!         // 2. Collect filesystem and memory blob paths
//!         // 3. Return SnapshotArtifacts with blob references
//!         todo!("implement snapshot capture for your backend")
//!     }
//!
//!     async fn validate_restore(
//!         &self,
//!         artifacts: &SnapshotArtifacts,
//!         host: &pico_image::warm_snapshot::HostContext,
//!     ) -> WarmSnapshotResult<RestoreValidationReport> {
//!         // Perform an actual restore and measure latency
//!         todo!("implement restore validation for your backend")
//!     }
//!
//!     async fn shutdown_guest(&self, ctx: &GuestContext) -> WarmSnapshotResult<()> {
//!         // Graceful shutdown of the booted VM
//!         todo!("implement guest shutdown for your backend")
//!     }
//! }
//! ```

pub mod compat;
pub mod config;
pub mod error;
pub mod generator;
pub mod validation;

pub use compat::{
    build_compatibility_record, build_warm_snapshot_metadata, compute_snapshot_integrity,
    validate_secret_exclusion, validate_warm_snapshot_compatibility,
};
pub use config::WarmSnapshotConfig;
pub use error::{WarmSnapshotError, WarmSnapshotResult};
pub use generator::{
    GuestContext, HostContext, ImageArtifactSet, SnapshotArtifacts, SnapshotBlobRef,
    WarmSnapshotBackend, WarmSnapshotGenerator, WarmSnapshotOutput,
};
pub use validation::{
    RestoreValidationReport, run_restore_validation, validate_promotion_readiness,
    validate_restore_compatibility, validate_restore_latency,
};

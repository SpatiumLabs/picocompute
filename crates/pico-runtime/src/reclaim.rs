//! Backend-specific reclaim behind the suspend contract.
//!
//! Container sandboxes reclaim through cgroup and swap pressure while the
//! frozen cgroup preserves execution state. MicroVM sandboxes reclaim
//! through snapshot plus terminate plus on-demand restore. Both paths
//! require the `memory` profile, reject cross-backend restore, and keep
//! the Pico resume contract: fresh boot identity, fresh protocol session,
//! current policy epoch, rebuilt network and credentials, mandatory
//! `ResumeNotify`, and restore-validation gates.

use pico_core::{
    ReclaimStrategy, RuntimeType, SnapshotProfile, reclaim_strategy_for_runtime,
    require_memory_profile_for_reclaim, require_same_backend_for_restore,
};

/// Estimated bytes freed by reclaiming one sandbox.
///
/// Pure helper for audit and metrics. The estimate equals the sandbox
/// memory reservation; actual host savings depend on swap and page cache.
#[must_use]
pub fn estimate_reclaimed_bytes(memory_mb: u64) -> u64 {
    memory_mb.saturating_mul(1_048_576)
}

/// MicroVM reclaim handle: snapshot plus terminate plus on-demand restore.
///
/// Captured after a successful suspend. The VMM process is terminated to
/// free host memory, but the immutable snapshot plus workspace reference
/// preserves execution state. Resume restores on the same backend family
/// and runs the full validation gate list before `Running`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MicroVmReclaimHandle {
    /// Sandbox that was reclaimed.
    pub sandbox_id: String,
    /// Immutable session snapshot holding memory and device state.
    pub snapshot_id: String,
    /// Backend family that captured the snapshot.
    pub capture_backend: RuntimeType,
    /// State profile of the snapshot. Must be `memory`.
    pub profile: SnapshotProfile,
}

impl MicroVmReclaimHandle {
    /// Plans a microVM reclaim.
    ///
    /// Fails when the profile is not `memory` (no silent filesystem
    /// fallback) or when ids are empty. The caller must suspend first and
    /// terminate only after the snapshot is durable.
    pub fn plan(
        sandbox_id: &str,
        snapshot_id: &str,
        capture_backend: RuntimeType,
        profile: SnapshotProfile,
    ) -> Result<Self, ReclaimError> {
        require_memory_profile_for_reclaim(profile)
            .map_err(|err| ReclaimError::Contract(err.to_string()))?;
        if sandbox_id.is_empty() || snapshot_id.is_empty() {
            return Err(ReclaimError::InvalidHandle(
                "sandbox and snapshot ids must be non-empty".into(),
            ));
        }
        if reclaim_strategy_for_runtime(capture_backend)
            != ReclaimStrategy::MicroVmSnapshotTerminate
        {
            return Err(ReclaimError::InvalidHandle(format!(
                "backend {capture_backend} does not use microVM reclaim"
            )));
        }
        Ok(Self {
            sandbox_id: sandbox_id.to_string(),
            snapshot_id: snapshot_id.to_string(),
            capture_backend,
            profile,
        })
    }

    /// Validates an on-demand restore against the capture backend.
    ///
    /// Rejects cross-backend restore, wrong profile, and sandbox mismatch
    /// before any blob I/O. Policy-epoch freshness and the remaining
    /// restore gates run in the host restore path.
    pub fn validate_restore(
        &self,
        target_sandbox_id: &str,
        target_backend: RuntimeType,
    ) -> Result<(), ReclaimError> {
        if self.sandbox_id != target_sandbox_id {
            return Err(ReclaimError::SandboxMismatch {
                expected: self.sandbox_id.clone(),
                actual: target_sandbox_id.to_string(),
            });
        }
        require_same_backend_for_restore(self.capture_backend, target_backend)
            .map_err(|err| ReclaimError::Contract(err.to_string()))?;
        require_memory_profile_for_reclaim(self.profile)
            .map_err(|err| ReclaimError::Contract(err.to_string()))?;
        Ok(())
    }
}

/// Container reclaim handle: cgroup plus swap.
///
/// Captured after a successful suspend. The frozen cgroup plus swap
/// backing preserves execution state while `memory.high` throttle and
/// `memory.reclaim` free host memory. Resume prefetches hot pages with
/// `MADV_WILLNEED` before execution resumes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerReclaimHandle {
    /// Sandbox that was reclaimed.
    pub sandbox_id: String,
    /// Target written to `memory.high` during reclaim.
    pub memory_high_bytes: u64,
    /// Bytes requested through `memory.reclaim`.
    pub reclaim_bytes: u64,
}

impl ContainerReclaimHandle {
    /// Plans a container reclaim from the sandbox memory reservation.
    pub fn plan(sandbox_id: &str, memory_limit_bytes: u64) -> Result<Self, ReclaimError> {
        if sandbox_id.is_empty() {
            return Err(ReclaimError::InvalidHandle(
                "sandbox id must be non-empty".into(),
            ));
        }
        let plan = pico_core::cgroups::container_reclaim_plan(memory_limit_bytes)
            .map_err(|err| ReclaimError::InvalidHandle(err.to_string()))?;
        Ok(Self {
            sandbox_id: sandbox_id.to_string(),
            memory_high_bytes: plan.memory_high_bytes,
            reclaim_bytes: plan.reclaim_bytes,
        })
    }
}

/// Typed reclaim failures.
///
/// Maps to `SandboxError::Unprocessable` for contract violations (wrong
/// profile, cross-backend, wrong strategy) so callers fail closed with a
/// retryable-safe error instead of downgrading semantics.
#[derive(Debug, thiserror::Error)]
pub enum ReclaimError {
    /// Suspend-contract violation: wrong profile, cross-backend, or
    /// backend-strategy mismatch.
    #[error("reclaim contract violation: {0}")]
    Contract(String),
    /// Restore requested for a different sandbox than the handle.
    #[error("reclaim handle sandbox mismatch: expected {expected}, got {actual}")]
    SandboxMismatch { expected: String, actual: String },
    /// Malformed handle (empty ids, unsupported backend for strategy).
    #[error("invalid reclaim handle: {0}")]
    InvalidHandle(String),
}

impl From<ReclaimError> for pico_core::SandboxError {
    fn from(err: ReclaimError) -> Self {
        match err {
            ReclaimError::Contract(msg) => Self::Unprocessable(msg),
            ReclaimError::SandboxMismatch { expected, actual } => Self::Unprocessable(format!(
                "reclaim handle sandbox mismatch: expected {expected}, got {actual}"
            )),
            ReclaimError::InvalidHandle(msg) => Self::BadRequest(msg),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn microvm_reclaim_requires_memory_profile() {
        let err = MicroVmReclaimHandle::plan(
            "sbx_abc",
            "snap_1",
            RuntimeType::Firecracker,
            SnapshotProfile::Filesystem,
        )
        .unwrap_err();
        assert!(matches!(err, ReclaimError::Contract(_)));
    }

    #[test]
    fn microvm_reclaim_rejects_container_backend() {
        let err = MicroVmReclaimHandle::plan(
            "sbx_abc",
            "snap_1",
            RuntimeType::GVisor,
            SnapshotProfile::Memory,
        )
        .unwrap_err();
        assert!(matches!(err, ReclaimError::InvalidHandle(_)));
    }

    #[test]
    fn microvm_restore_rejects_cross_backend() {
        let handle = MicroVmReclaimHandle::plan(
            "sbx_abc",
            "snap_1",
            RuntimeType::Firecracker,
            SnapshotProfile::Memory,
        )
        .unwrap();
        assert!(
            handle
                .validate_restore("sbx_abc", RuntimeType::Firecracker)
                .is_ok()
        );
        assert!(
            handle
                .validate_restore("sbx_abc", RuntimeType::Qemu)
                .is_err()
        );
        assert!(
            handle
                .validate_restore("sbx_other", RuntimeType::Firecracker)
                .is_err()
        );
    }

    #[test]
    fn container_reclaim_plan_wires_cgroup_math() {
        let handle = ContainerReclaimHandle::plan("sbx_abc", 512 * 1_048_576).unwrap();
        assert_eq!(handle.memory_high_bytes, 256 * 1_048_576);
        assert_eq!(handle.reclaim_bytes, 512 * 1_048_576);
        assert!(ContainerReclaimHandle::plan("", 512).is_err());
        assert!(ContainerReclaimHandle::plan("sbx_abc", 0).is_err());
    }

    #[test]
    fn reclaim_estimate_matches_reservation() {
        assert_eq!(estimate_reclaimed_bytes(512), 512 * 1_048_576);
        assert_eq!(estimate_reclaimed_bytes(0), 0);
    }
}

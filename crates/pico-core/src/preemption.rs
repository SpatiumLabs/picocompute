//! Job-scoped preemption signal and backend-specific reclaim policy.
//!
//! The control plane pauses a whole job (a set of sandboxes that share a
//! training or rollout step) when preemptible capacity is reclaimed. The
//! signal travels control plane to host-agent to sandboxd, reusing the
//! existing per-sandbox suspend contract: operation fence, exec drain,
//! cooperative quiesce, `memory` state profile, fresh authority on resume,
//! and mandatory `ResumeNotify`. This module owns the job envelope,
//! the per-backend reclaim mapping, and the restore-validation gate list
//! so every layer agrees on the same contract.
//!
//! Reclaim mapping:
//! - container-backed sandboxes reclaim through cgroup and swap pressure
//!   (`pause` plus swap plus `memory.reclaim` with `MADV_WILLNEED`
//!   prefetch on resume).
//! - microVM-backed sandboxes reclaim through snapshot plus terminate plus
//!   on-demand restore.
//!
//! Neither path weakens suspend semantics: a `filesystem` profile request
//! fails instead of falling back, cross-backend restore is rejected, and
//! resume always revalidates, reauthenticates, and refreshes policy epoch,
//! network, credentials, and session identity.

use serde::{Deserialize, Serialize};

use crate::error::{Result, SandboxError};
use crate::identity::FencingToken;
use crate::runtime::RuntimeType;
use crate::snapshot::SnapshotProfile;
use crate::workspace::validate_sandbox_id;

/// Prefix for job identifiers.
pub const JOB_ID_PREFIX: &str = "job_";

/// Maximum job-scoped pause/resume deadline in seconds.
///
/// Matches the per-sandbox suspend/resume budget so a bulk signal never
/// smuggles a longer deadline past the sandboxd absolute-deadline check.
pub const MAX_JOB_DEADLINE_SECS: u64 = 300;

/// Default job pause/resume deadline in seconds.
///
/// Matches `DEFAULT_SUSPEND_TIMEOUT_SECS` and `DEFAULT_RESUME_TIMEOUT_SECS`
/// in the host agent.
pub const DEFAULT_JOB_DEADLINE_SECS: u64 = 120;

/// Maximum sandboxes in one job signal.
///
/// Bounds the fan-out so one control-plane request cannot wedge a host
/// with an unbounded suspend loop.
pub const MAX_JOB_SANDBOXES: usize = 256;

/// Validates a job identifier.
///
/// Jobs use `job_` plus ASCII alphanumerics and `_`, mirroring the sandbox
/// id rules so ids stay single safe path components.
pub fn validate_job_id(id: &str) -> Result<()> {
    if id.contains("..") || id.contains('/') || id.contains('\\') {
        return Err(SandboxError::PathEscape(id.into()));
    }
    let Some(suffix) = id.strip_prefix(JOB_ID_PREFIX) else {
        return Err(SandboxError::BadRequest(format!("invalid job id: {id}")));
    };
    if suffix.is_empty()
        || suffix.len() > 96
        || !suffix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err(SandboxError::BadRequest(format!("invalid job id: {id}")));
    }
    Ok(())
}

/// Which host-side reclaim mechanism applies to a sandbox.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ReclaimStrategy {
    /// Container path: cgroup freeze plus swap plus `memory.reclaim`,
    /// with `MADV_WILLNEED` prefetch on resume.
    ContainerSwapReclaim,
    /// MicroVM path: snapshot plus terminate plus on-demand restore.
    MicroVmSnapshotTerminate,
    /// Fallback for missing sandboxes where the runtime is unknown.
    ///
    /// Used only in job outcomes when the member lookup fails before the
    /// runtime is known, so the outcome does not misattribute a strategy.
    Unknown,
}

impl ReclaimStrategy {
    /// Human-readable strategy name for audit and metrics.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContainerSwapReclaim => "container_swap_reclaim",
            Self::MicroVmSnapshotTerminate => "microvm_snapshot_terminate",
            Self::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for ReclaimStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Maps a runtime family to its reclaim strategy.
///
/// gVisor is the container-backed path in this repo. Firecracker, QEMU,
/// and remote Firecracker are microVM paths. The mapping is total so a
/// new backend cannot silently fall through to the wrong mechanism.
#[must_use]
pub fn reclaim_strategy_for_runtime(runtime: RuntimeType) -> ReclaimStrategy {
    match runtime {
        RuntimeType::GVisor => ReclaimStrategy::ContainerSwapReclaim,
        RuntimeType::Firecracker | RuntimeType::Qemu | RuntimeType::RemoteFirecracker => {
            ReclaimStrategy::MicroVmSnapshotTerminate
        }
    }
}

/// Validates a tenant identifier for job scoping.
///
/// Jobs are single-tenant: all members must belong to the signal tenant
/// when the signal carries one. Tenant ids use `tnt_` plus ASCII
/// alphanumerics and `_`.
pub fn validate_job_tenant_id(id: &str) -> Result<()> {
    if id.contains("..") || id.contains('/') || id.contains('\\') {
        return Err(SandboxError::PathEscape(id.into()));
    }
    let Some(suffix) = id.strip_prefix("tnt_") else {
        return Err(SandboxError::BadRequest(format!("invalid tenant id: {id}")));
    };
    if suffix.is_empty()
        || suffix.len() > 96
        || !suffix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err(SandboxError::BadRequest(format!("invalid tenant id: {id}")));
    }
    Ok(())
}

/// Job-scoped pause signal from the control plane to a host.
///
/// The host fans this out to one fenced `Suspend` per member sandbox. Each
/// member keeps its own fencing, policy-epoch, and deadline checks in
/// sandboxd; this envelope only carries the shared job identity and the
/// base fencing token the per-sandbox tokens derive from.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JobPauseSignal {
    /// Job identity shared by all member sandboxes.
    pub job_id: String,
    /// Member sandbox ids. Must be non-empty, unique, and valid.
    pub sandbox_ids: Vec<String>,
    /// Base fencing token. Must be newer than every member's current token.
    pub fencing_token: FencingToken,
    /// Current policy epoch at the control plane.
    pub policy_epoch: u64,
    /// Per-sandbox deadline in seconds. Zero means `DEFAULT_JOB_DEADLINE_SECS`.
    #[serde(default)]
    pub deadline_secs: u64,
    /// Operator-visible reason (e.g. `preemptible-reclaim`).
    pub reason: String,
    /// Optional tenant scope. When present, every member must belong to it.
    #[serde(default)]
    pub tenant_id: Option<String>,
}

impl JobPauseSignal {
    /// Effective per-sandbox deadline, applying the default when zero.
    #[must_use]
    pub fn effective_deadline_secs(&self) -> u64 {
        if self.deadline_secs == 0 {
            DEFAULT_JOB_DEADLINE_SECS
        } else {
            self.deadline_secs
        }
    }

    /// Validates the envelope without touching host state.
    ///
    /// Fencing freshness against each member's ledger and policy-epoch
    /// monotonicity are enforced downstream by sandboxd; this only rejects
    /// malformed envelopes fail-closed before any side effect.
    pub fn validate(&self) -> Result<()> {
        validate_job_id(&self.job_id)?;
        if let Some(ref tenant) = self.tenant_id {
            validate_job_tenant_id(tenant)?;
        }
        if self.sandbox_ids.is_empty() {
            return Err(SandboxError::BadRequest(
                "job pause requires at least one sandbox".into(),
            ));
        }
        if self.sandbox_ids.len() > MAX_JOB_SANDBOXES {
            return Err(SandboxError::BadRequest(format!(
                "job pause exceeds {} sandboxes",
                MAX_JOB_SANDBOXES
            )));
        }
        let mut seen = std::collections::BTreeSet::new();
        for id in &self.sandbox_ids {
            validate_sandbox_id(id)?;
            if !seen.insert(id) {
                return Err(SandboxError::BadRequest(format!(
                    "duplicate sandbox in job pause: {id}"
                )));
            }
        }
        if self.policy_epoch == 0 {
            return Err(SandboxError::BadRequest(
                "job pause policy epoch must be non-zero".into(),
            ));
        }
        if self.effective_deadline_secs() == 0
            || self.effective_deadline_secs() > MAX_JOB_DEADLINE_SECS
        {
            return Err(SandboxError::BadRequest(format!(
                "job pause deadline must be 1..={}s",
                MAX_JOB_DEADLINE_SECS
            )));
        }
        if self.reason.trim().is_empty() {
            return Err(SandboxError::BadRequest(
                "job pause reason must be non-empty".into(),
            ));
        }
        Ok(())
    }

    /// Derives the per-sandbox fencing token for member `index`.
    ///
    /// The base token is bumped by the member position so concurrent members
    /// carry distinct tokens while preserving the job ordering. Sequence
    /// overflow saturates instead of wrapping so a huge job cannot wrap
    /// around to a stale token.
    #[must_use]
    pub fn token_for_member(&self, index: usize) -> FencingToken {
        let bump = u64::try_from(index).unwrap_or(u64::MAX);
        FencingToken {
            epoch: self.fencing_token.epoch,
            sequence: self.fencing_token.sequence.saturating_add(bump),
        }
    }
}

/// Job-scoped resume signal from the control plane to a host.
///
/// Mirrors [`JobPauseSignal`] but fans out to one fenced `Resume` per
/// member. Resume revalidates, reauthenticates, refreshes policy epoch,
/// rebuilds network and credentials, and completes `ResumeNotify` before
/// reporting `Running`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JobResumeSignal {
    /// Job identity paused earlier.
    pub job_id: String,
    /// Member sandbox ids to resume.
    pub sandbox_ids: Vec<String>,
    /// Base fencing token, newer than the pause tokens.
    pub fencing_token: FencingToken,
    /// Current policy epoch at resume time (refresh, not restore).
    pub policy_epoch: u64,
    /// Per-sandbox deadline in seconds. Zero means `DEFAULT_JOB_DEADLINE_SECS`.
    #[serde(default)]
    pub deadline_secs: u64,
    /// Operator-visible reason (e.g. `capacity-restored`).
    pub reason: String,
    /// Optional tenant scope. When present, every member must belong to it.
    #[serde(default)]
    pub tenant_id: Option<String>,
}

impl JobResumeSignal {
    /// Effective per-sandbox deadline, applying the default when zero.
    #[must_use]
    pub fn effective_deadline_secs(&self) -> u64 {
        if self.deadline_secs == 0 {
            DEFAULT_JOB_DEADLINE_SECS
        } else {
            self.deadline_secs
        }
    }

    /// Validates the envelope without touching host state.
    pub fn validate(&self) -> Result<()> {
        validate_job_id(&self.job_id)?;
        if let Some(ref tenant) = self.tenant_id {
            validate_job_tenant_id(tenant)?;
        }
        if self.sandbox_ids.is_empty() {
            return Err(SandboxError::BadRequest(
                "job resume requires at least one sandbox".into(),
            ));
        }
        if self.sandbox_ids.len() > MAX_JOB_SANDBOXES {
            return Err(SandboxError::BadRequest(format!(
                "job resume exceeds {} sandboxes",
                MAX_JOB_SANDBOXES
            )));
        }
        let mut seen = std::collections::BTreeSet::new();
        for id in &self.sandbox_ids {
            validate_sandbox_id(id)?;
            if !seen.insert(id) {
                return Err(SandboxError::BadRequest(format!(
                    "duplicate sandbox in job resume: {id}"
                )));
            }
        }
        if self.policy_epoch == 0 {
            return Err(SandboxError::BadRequest(
                "job resume policy epoch must be non-zero".into(),
            ));
        }
        if self.effective_deadline_secs() == 0
            || self.effective_deadline_secs() > MAX_JOB_DEADLINE_SECS
        {
            return Err(SandboxError::BadRequest(format!(
                "job resume deadline must be 1..={}s",
                MAX_JOB_DEADLINE_SECS
            )));
        }
        if self.reason.trim().is_empty() {
            return Err(SandboxError::BadRequest(
                "job resume reason must be non-empty".into(),
            ));
        }
        Ok(())
    }

    /// Derives the per-sandbox fencing token for member `index`.
    #[must_use]
    pub fn token_for_member(&self, index: usize) -> FencingToken {
        let bump = u64::try_from(index).unwrap_or(u64::MAX);
        FencingToken {
            epoch: self.fencing_token.epoch,
            sequence: self.fencing_token.sequence.saturating_add(bump),
        }
    }
}

/// Per-sandbox outcome of a job pause or resume fan-out.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JobMemberOutcome {
    /// Member sandbox id.
    pub sandbox_id: String,
    /// Whether the member reached the target state.
    pub succeeded: bool,
    /// Reclaim strategy applied to this member.
    pub strategy: ReclaimStrategy,
    /// Human-readable detail (empty on success).
    pub message: String,
    /// MicroVM snapshot id for reclaim plus restore correlation.
    ///
    /// Present only for microVM pause members where a reclaim handle was
    /// planned. Absent for containers, unknown runtimes, and failures
    /// before planning.
    #[serde(default)]
    pub snapshot_id: Option<String>,
}

/// Aggregate outcome of a job pause or resume.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JobOutcome {
    /// Job identity.
    pub job_id: String,
    /// Per-member outcomes in request order.
    pub members: Vec<JobMemberOutcome>,
}

impl JobOutcome {
    /// True when every member succeeded.
    #[must_use]
    pub fn all_succeeded(&self) -> bool {
        self.members.iter().all(|m| m.succeeded)
    }

    /// Ids of members that succeeded.
    #[must_use]
    pub fn succeeded_ids(&self) -> Vec<&str> {
        self.members
            .iter()
            .filter(|m| m.succeeded)
            .map(|m| m.sandbox_id.as_str())
            .collect()
    }

    /// Ids of members that failed.
    #[must_use]
    pub fn failed_ids(&self) -> Vec<&str> {
        self.members
            .iter()
            .filter(|m| !m.succeeded)
            .map(|m| m.sandbox_id.as_str())
            .collect()
    }
}

/// Audit operation names for job preemption.
///
/// Per-sandbox audit still uses the existing `LifecycleTransition` and
/// `SnapshotOperation` events; these names tag the job envelope that
/// caused them so operators can correlate a bulk pause with its members.
pub mod job_audit_ops {
    /// Job pause envelope admitted by the control plane.
    pub const JOB_PAUSE: &str = "job.pause";
    /// Job resume envelope admitted by the control plane.
    pub const JOB_RESUME: &str = "job.resume";
    /// Container reclaim step (cgroup plus swap) after suspend.
    pub const CONTAINER_RECLAIM: &str = "job.reclaim_container";
    /// MicroVM reclaim step (snapshot plus terminate) after suspend.
    pub const MICROVM_RECLAIM: &str = "job.reclaim_microvm";
    /// MicroVM restore step (on-demand restore) before resume.
    pub const MICROVM_RESTORE: &str = "job.restore_microvm";
    /// Prefetch step (`MADV_WILLNEED`) after container resume.
    pub const CONTAINER_PREFETCH: &str = "job.prefetch_container";
}

/// Restore-validation gates a resume must pass.
///
/// Mirrors the snapshot restore checklist so a preemption resume cannot
/// take a shortcut around compatibility, integrity, or authority refresh.
/// The host-agent resume path must enforce every gate; the list is exposed
/// here so tests and audit can assert coverage.
#[must_use]
pub fn restore_validation_gates() -> &'static [&'static str] {
    &[
        "tenant_identity",
        "snapshot_readiness",
        "snapshot_lineage",
        "encryption_key_availability",
        "artifact_integrity",
        "image_compatibility",
        "backend_compatibility",
        "kernel_compatibility",
        "guest_agent_compatibility",
        "protocol_compatibility",
        "cpu_shape",
        "device_model",
        "memory_shape",
        "workload_policy",
        "excluded_state",
        "fresh_policy_epoch",
        "fresh_network_identity",
        "fresh_credentials",
        "resume_notify",
        "health_validation",
    ]
}

/// Rejects a reclaim request that does not carry the `memory` profile.
///
/// Lifecycle suspend and resume require `memory` because `Suspended`
/// preserves guest memory and device state. A `filesystem` request fails
/// here instead of silently downgrading to a boot path.
pub fn require_memory_profile_for_reclaim(profile: SnapshotProfile) -> Result<()> {
    if profile.supports_lifecycle_suspend() {
        Ok(())
    } else {
        Err(SandboxError::Unprocessable(format!(
            "reclaim requires the memory profile, got {} (no silent filesystem fallback)",
            profile.as_str()
        )))
    }
}

/// Rejects cross-backend restore.
///
/// A snapshot captured on one backend family must never restore on another.
/// Callers pass the capture backend and the resume target; a mismatch fails
/// instead of attempting translation.
pub fn require_same_backend_for_restore(capture: RuntimeType, target: RuntimeType) -> Result<()> {
    if capture == target {
        Ok(())
    } else {
        Err(SandboxError::Unprocessable(format!(
            "cross-backend restore rejected: capture={capture}, target={target}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pause_signal() -> JobPauseSignal {
        JobPauseSignal {
            job_id: "job_train_42".into(),
            sandbox_ids: vec!["sbx_abc123".into(), "sbx_def456".into()],
            fencing_token: FencingToken {
                epoch: 7,
                sequence: 3,
            },
            policy_epoch: 7,
            deadline_secs: 120,
            reason: "preemptible-reclaim".into(),
            tenant_id: None,
        }
    }

    fn resume_signal() -> JobResumeSignal {
        JobResumeSignal {
            job_id: "job_train_42".into(),
            sandbox_ids: vec!["sbx_abc123".into()],
            fencing_token: FencingToken {
                epoch: 7,
                sequence: 10,
            },
            policy_epoch: 8,
            deadline_secs: 120,
            reason: "capacity-restored".into(),
            tenant_id: None,
        }
    }

    #[test]
    fn job_id_validation() {
        assert!(validate_job_id("job_train_42").is_ok());
        for bad in [
            "",
            "sbx_abc",
            "job-",
            "job_",
            "job_has space",
            "job_has/slash",
            "../job_escape",
            "job_has.dot",
        ] {
            assert!(validate_job_id(bad).is_err(), "must reject {bad:?}");
        }
    }

    #[test]
    fn pause_signal_validates_members() {
        assert!(pause_signal().validate().is_ok());
        let mut empty = pause_signal();
        empty.sandbox_ids.clear();
        assert!(empty.validate().is_err());
        let mut dup = pause_signal();
        dup.sandbox_ids.push("sbx_abc123".into());
        assert!(dup.validate().is_err());
        let mut bad_id = pause_signal();
        bad_id.sandbox_ids[0] = "bad".into();
        assert!(bad_id.validate().is_err());
        let mut bad_epoch = pause_signal();
        bad_epoch.policy_epoch = 0;
        assert!(bad_epoch.validate().is_err());
        let mut default_deadline = pause_signal();
        default_deadline.deadline_secs = 0;
        assert!(default_deadline.validate().is_ok());
        assert_eq!(
            default_deadline.effective_deadline_secs(),
            DEFAULT_JOB_DEADLINE_SECS
        );
        let mut bad_deadline = pause_signal();
        bad_deadline.deadline_secs = MAX_JOB_DEADLINE_SECS + 1;
        assert!(bad_deadline.validate().is_err());
        let mut bad_reason = pause_signal();
        bad_reason.reason = "  ".into();
        assert!(bad_reason.validate().is_err());
        let mut bad_tenant = pause_signal();
        bad_tenant.tenant_id = Some("bad".into());
        assert!(bad_tenant.validate().is_err());
        let mut ok_tenant = pause_signal();
        ok_tenant.tenant_id = Some("tnt_abc123".into());
        assert!(ok_tenant.validate().is_ok());
    }

    #[test]
    fn resume_signal_validates_members() {
        assert!(resume_signal().validate().is_ok());
        let mut empty = resume_signal();
        empty.sandbox_ids.clear();
        assert!(empty.validate().is_err());
    }

    #[test]
    fn member_tokens_are_unique_and_ordered() {
        let signal = pause_signal();
        let first = signal.token_for_member(0);
        let second = signal.token_for_member(1);
        assert_eq!(first, signal.fencing_token);
        assert!(second.is_newer_than(&first));
    }

    #[test]
    fn reclaim_strategy_mapping_is_total() {
        assert_eq!(
            reclaim_strategy_for_runtime(RuntimeType::GVisor),
            ReclaimStrategy::ContainerSwapReclaim
        );
        for runtime in [
            RuntimeType::Firecracker,
            RuntimeType::Qemu,
            RuntimeType::RemoteFirecracker,
        ] {
            assert_eq!(
                reclaim_strategy_for_runtime(runtime),
                ReclaimStrategy::MicroVmSnapshotTerminate
            );
        }
    }

    #[test]
    fn memory_profile_required_for_reclaim() {
        assert!(require_memory_profile_for_reclaim(SnapshotProfile::Memory).is_ok());
        assert!(require_memory_profile_for_reclaim(SnapshotProfile::Filesystem).is_err());
    }

    #[test]
    fn cross_backend_restore_rejected() {
        assert!(
            require_same_backend_for_restore(RuntimeType::Firecracker, RuntimeType::Firecracker)
                .is_ok()
        );
        assert!(
            require_same_backend_for_restore(RuntimeType::Firecracker, RuntimeType::Qemu).is_err()
        );
    }

    #[test]
    fn job_outcome_aggregation() {
        let outcome = JobOutcome {
            job_id: "job_x".into(),
            members: vec![
                JobMemberOutcome {
                    sandbox_id: "sbx_a".into(),
                    succeeded: true,
                    strategy: ReclaimStrategy::ContainerSwapReclaim,
                    message: String::new(),
                    snapshot_id: None,
                },
                JobMemberOutcome {
                    sandbox_id: "sbx_b".into(),
                    succeeded: false,
                    strategy: ReclaimStrategy::MicroVmSnapshotTerminate,
                    message: "suspend timed out".into(),
                    snapshot_id: None,
                },
            ],
        };
        assert!(!outcome.all_succeeded());
        assert_eq!(outcome.succeeded_ids(), vec!["sbx_a"]);
        assert_eq!(outcome.failed_ids(), vec!["sbx_b"]);
    }

    #[test]
    fn unknown_strategy_marks_missing_runtime() {
        assert_eq!(ReclaimStrategy::Unknown.as_str(), "unknown");
    }

    #[test]
    fn restore_gates_cover_authority_refresh() {
        let gates = restore_validation_gates();
        for required in [
            "fresh_policy_epoch",
            "fresh_network_identity",
            "fresh_credentials",
            "resume_notify",
            "backend_compatibility",
            "excluded_state",
        ] {
            assert!(gates.contains(&required), "missing gate {required}");
        }
    }
}

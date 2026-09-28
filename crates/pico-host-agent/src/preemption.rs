//! Job-scoped pause and resume orchestration helpers.
//!
//! The control plane sends one [`JobPauseSignal`] or [`JobResumeSignal`]
//! per job. The host fans the signal out to one fenced `Suspend` or
//! `Resume` per member sandbox, reusing the existing sandboxd
//! `CommandMeta` checks (fencing monotonicity, policy-epoch monotonicity,
//! absolute deadline, operation identity). Per-backend reclaim runs after
//! a successful suspend: containers through cgroup plus swap pressure,
//! microVMs through snapshot plus terminate plus on-demand restore. Resume
//! always refreshes authority (policy epoch, network, credentials,
//! session) and completes `ResumeNotify` before reporting `Running`.

use std::time::Duration;

use pico_core::{
    JobMemberOutcome, JobOutcome, JobPauseSignal, JobResumeSignal, ReclaimStrategy,
    SnapshotProfile, reclaim_strategy_for_runtime, require_memory_profile_for_reclaim,
    require_same_backend_for_restore, restore_validation_gates,
};

/// Per-member fencing and deadline derived from a job signal.
#[derive(Debug, Clone, Copy)]
pub struct MemberCommand {
    /// Fencing token for this member (base token bumped by position).
    pub token: pico_core::FencingToken,
    /// Policy epoch from the job signal (current at control plane).
    pub policy_epoch: u64,
    /// Absolute deadline for the sandboxd operation.
    pub deadline: Duration,
}

impl MemberCommand {
    /// Derives the command for member `index` from a pause signal.
    pub fn for_pause(signal: &JobPauseSignal, index: usize) -> Self {
        Self {
            token: signal.token_for_member(index),
            policy_epoch: signal.policy_epoch,
            deadline: Duration::from_secs(signal.deadline_secs),
        }
    }

    /// Derives the command for member `index` from a resume signal.
    pub fn for_resume(signal: &JobResumeSignal, index: usize) -> Self {
        Self {
            token: signal.token_for_member(index),
            policy_epoch: signal.policy_epoch,
            deadline: Duration::from_secs(signal.deadline_secs),
        }
    }
}

/// Builds the aggregate outcome for a job fan-out.
///
/// Members stay in request order so operators can correlate the job
/// envelope with per-sandbox audit events.
pub fn build_job_outcome(
    job_id: &str,
    results: Vec<(String, ReclaimStrategy, Result<(), String>)>,
) -> JobOutcome {
    let members = results
        .into_iter()
        .map(|(sandbox_id, strategy, result)| {
            let (succeeded, message) = match result {
                Ok(()) => (true, String::new()),
                Err(message) => (false, message),
            };
            JobMemberOutcome {
                sandbox_id,
                succeeded,
                strategy,
                message,
            }
        })
        .collect();
    JobOutcome {
        job_id: job_id.to_string(),
        members,
    }
}

/// Validates that a reclaim request keeps the suspend contract.
///
/// Rejects `filesystem` profiles (no silent fallback) and cross-backend
/// restore before any side effect. The caller passes the capture backend,
/// the resume target backend, and the requested profile.
pub fn validate_reclaim_contract(
    capture: pico_core::RuntimeType,
    target: pico_core::RuntimeType,
    profile: SnapshotProfile,
) -> Result<(), pico_core::SandboxError> {
    require_memory_profile_for_reclaim(profile)?;
    require_same_backend_for_restore(capture, target)?;
    Ok(())
}

/// Returns the reclaim strategy for a runtime, for audit and metrics.
pub fn strategy_for_runtime(runtime: pico_core::RuntimeType) -> ReclaimStrategy {
    reclaim_strategy_for_runtime(runtime)
}

/// Asserts that resume covers every restore-validation gate.
///
/// The host resume path must enforce the full gate list; this helper lets
/// tests and audit assert coverage without duplicating the list.
pub fn assert_restore_gates_covered(gates: &[&str]) -> Result<(), String> {
    for required in restore_validation_gates() {
        if !gates.contains(required) {
            return Err(format!("restore gate not covered: {required}"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pico_core::{FencingToken, RuntimeType};

    fn pause_signal() -> JobPauseSignal {
        JobPauseSignal {
            job_id: "job_train_1".into(),
            sandbox_ids: vec!["sbx_aaa111".into(), "sbx_bbb222".into()],
            fencing_token: FencingToken {
                epoch: 5,
                sequence: 10,
            },
            policy_epoch: 5,
            deadline_secs: 120,
            reason: "preemptible-reclaim".into(),
        }
    }

    fn resume_signal() -> JobResumeSignal {
        JobResumeSignal {
            job_id: "job_train_1".into(),
            sandbox_ids: vec!["sbx_aaa111".into()],
            fencing_token: FencingToken {
                epoch: 5,
                sequence: 20,
            },
            policy_epoch: 6,
            deadline_secs: 120,
            reason: "capacity-restored".into(),
        }
    }

    #[test]
    fn member_commands_derive_fencing_and_deadline() {
        let signal = pause_signal();
        signal.validate().unwrap();
        let first = MemberCommand::for_pause(&signal, 0);
        let second = MemberCommand::for_pause(&signal, 1);
        assert_eq!(first.token, signal.fencing_token);
        assert!(second.token.is_newer_than(&first.token));
        assert_eq!(first.policy_epoch, 5);
        assert_eq!(first.deadline, Duration::from_secs(120));

        let resume = resume_signal();
        resume.validate().unwrap();
        let cmd = MemberCommand::for_resume(&resume, 0);
        assert_eq!(cmd.policy_epoch, 6);
    }

    #[test]
    fn job_outcome_preserves_order() {
        let outcome = build_job_outcome(
            "job_x",
            vec![
                (
                    "sbx_aaa111".into(),
                    ReclaimStrategy::ContainerSwapReclaim,
                    Ok(()),
                ),
                (
                    "sbx_bbb222".into(),
                    ReclaimStrategy::MicroVmSnapshotTerminate,
                    Err("suspend timed out".into()),
                ),
            ],
        );
        assert_eq!(outcome.job_id, "job_x");
        assert_eq!(outcome.members.len(), 2);
        assert!(!outcome.all_succeeded());
        assert_eq!(outcome.succeeded_ids(), vec!["sbx_aaa111"]);
    }

    #[test]
    fn reclaim_contract_rejects_weakening() {
        assert!(
            validate_reclaim_contract(
                RuntimeType::Firecracker,
                RuntimeType::Firecracker,
                SnapshotProfile::Memory,
            )
            .is_ok()
        );
        assert!(
            validate_reclaim_contract(
                RuntimeType::Firecracker,
                RuntimeType::Firecracker,
                SnapshotProfile::Filesystem,
            )
            .is_err()
        );
        assert!(
            validate_reclaim_contract(
                RuntimeType::Firecracker,
                RuntimeType::Qemu,
                SnapshotProfile::Memory,
            )
            .is_err()
        );
    }

    #[test]
    fn restore_gates_cover_authority_refresh() {
        let gates = restore_validation_gates();
        assert!(assert_restore_gates_covered(gates).is_ok());
        assert!(assert_restore_gates_covered(&["tenant_identity"]).is_err());
    }
}

use std::time::Instant;

use pico_core::{BackendError, RuntimeBackend, SandboxState};

use super::{ConformanceCheck, ConformanceProfile, ConformanceReport};

pub(super) async fn test_state_guards(
    backend: &dyn RuntimeBackend,
    profile: &ConformanceProfile,
    report: &mut ConformanceReport,
) {
    let t0 = Instant::now();
    match backend.state().await {
        Ok(SandboxState::Pending) => {
            report.add_check(ConformanceCheck::pass(
                "state-guards/initial-pending",
                t0.elapsed().as_millis() as u64,
            ));
        }
        Ok(_) => {
            report.add_check(ConformanceCheck::fail(
                "state-guards/initial-pending",
                "initial state is not Pending",
                t0.elapsed().as_millis() as u64,
            ));
        }
        Err(_) => {
            report.add_check(ConformanceCheck::pass(
                "state-guards/initial-pending",
                t0.elapsed().as_millis() as u64,
            ));
        }
    }

    let t0 = Instant::now();
    match backend.boot().await {
        Err(BackendError::InvalidState { .. })
        | Err(BackendError::Failed { .. })
        | Err(BackendError::Unsupported { .. }) => {
            report.add_check(ConformanceCheck::pass(
                "state-guards/boot-requires-prepare",
                t0.elapsed().as_millis() as u64,
            ));
        }
        Err(e) => {
            report.add_check(ConformanceCheck::fail(
                "state-guards/boot-requires-prepare",
                format!("expected InvalidState/Failed/Unsupported, got: {e}"),
                t0.elapsed().as_millis() as u64,
            ));
        }
        Ok(()) => {
            report.add_check(ConformanceCheck::fail(
                "state-guards/boot-requires-prepare",
                "boot succeeded without prepare",
                t0.elapsed().as_millis() as u64,
            ));
        }
    }

    let t0 = Instant::now();
    match backend.exec(profile.exec.clone()).await {
        Err(BackendError::InvalidState { .. })
        | Err(BackendError::Failed { .. })
        | Err(BackendError::Unsupported { .. }) => {
            report.add_check(ConformanceCheck::pass(
                "state-guards/exec-requires-running",
                t0.elapsed().as_millis() as u64,
            ));
        }
        Err(e) => {
            report.add_check(ConformanceCheck::fail(
                "state-guards/exec-requires-running",
                format!("expected InvalidState/Failed/Unsupported, got: {e}"),
                t0.elapsed().as_millis() as u64,
            ));
        }
        Ok(_) => {
            report.add_check(ConformanceCheck::fail(
                "state-guards/exec-requires-running",
                "exec succeeded without prepare+boot",
                t0.elapsed().as_millis() as u64,
            ));
        }
    }

    let t0 = Instant::now();
    match backend.suspend().await {
        Err(BackendError::InvalidState { .. })
        | Err(BackendError::Failed { .. })
        | Err(BackendError::Unsupported { .. }) => {
            report.add_check(ConformanceCheck::pass(
                "state-guards/suspend-requires-running",
                t0.elapsed().as_millis() as u64,
            ));
        }
        Err(e) => {
            report.add_check(ConformanceCheck::fail(
                "state-guards/suspend-requires-running",
                format!("expected InvalidState/Failed/Unsupported, got: {e}"),
                t0.elapsed().as_millis() as u64,
            ));
        }
        Ok(()) => {
            report.add_check(ConformanceCheck::fail(
                "state-guards/suspend-requires-running",
                "suspend succeeded without running state",
                t0.elapsed().as_millis() as u64,
            ));
        }
    }

    let t0 = Instant::now();
    match backend.resume().await {
        Err(BackendError::InvalidState { .. })
        | Err(BackendError::Failed { .. })
        | Err(BackendError::Unsupported { .. }) => {
            report.add_check(ConformanceCheck::pass(
                "state-guards/resume-requires-suspended",
                t0.elapsed().as_millis() as u64,
            ));
        }
        Err(e) => {
            report.add_check(ConformanceCheck::fail(
                "state-guards/resume-requires-suspended",
                format!("expected InvalidState/Failed/Unsupported, got: {e}"),
                t0.elapsed().as_millis() as u64,
            ));
        }
        Ok(()) => {
            report.add_check(ConformanceCheck::fail(
                "state-guards/resume-requires-suspended",
                "resume succeeded without suspended state",
                t0.elapsed().as_millis() as u64,
            ));
        }
    }

    let t0 = Instant::now();
    match backend.attach_transport().await {
        Err(BackendError::InvalidState { .. })
        | Err(BackendError::Failed { .. })
        | Err(BackendError::Unsupported { .. }) => {
            report.add_check(ConformanceCheck::pass(
                "state-guards/attach-requires-booting",
                t0.elapsed().as_millis() as u64,
            ));
        }
        Err(e) => {
            report.add_check(ConformanceCheck::fail(
                "state-guards/attach-requires-booting",
                format!("expected InvalidState/Failed/Unsupported, got: {e}"),
                t0.elapsed().as_millis() as u64,
            ));
        }
        Ok(_) => {
            report.add_check(ConformanceCheck::fail(
                "state-guards/attach-requires-booting",
                "attach_transport succeeded without prepared state",
                t0.elapsed().as_millis() as u64,
            ));
        }
    }

    if let Some(child_cfg) = &profile.fork_child {
        let t0 = Instant::now();
        match backend.fork(child_cfg).await {
            Err(BackendError::InvalidState { .. })
            | Err(BackendError::Failed { .. })
            | Err(BackendError::Unsupported { .. }) => {
                report.add_check(ConformanceCheck::pass(
                    "state-guards/fork-requires-running",
                    t0.elapsed().as_millis() as u64,
                ));
            }
            Err(e) => {
                report.add_check(ConformanceCheck::fail(
                    "state-guards/fork-requires-running",
                    format!("expected InvalidState/Failed/Unsupported, got: {e}"),
                    t0.elapsed().as_millis() as u64,
                ));
            }
            Ok(_) => {
                report.add_check(ConformanceCheck::fail(
                    "state-guards/fork-requires-running",
                    "fork succeeded without running state",
                    t0.elapsed().as_millis() as u64,
                ));
            }
        }
    }
}

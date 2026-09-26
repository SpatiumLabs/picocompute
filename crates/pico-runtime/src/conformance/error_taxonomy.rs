use hashbrown::HashSet;
use std::time::Instant;

use pico_core::{BackendError, BackendOperation, RuntimeBackend, SandboxState};

use super::{ConformanceCheck, ConformanceProfile, ConformanceReport};

pub(super) async fn test_error_taxonomy(
    backend: &dyn RuntimeBackend,
    _profile: &ConformanceProfile,
    report: &mut ConformanceReport,
) {
    let t0 = Instant::now();
    match backend.boot().await {
        Err(BackendError::InvalidState { expected, .. }) => {
            if expected.contains(&SandboxState::Preparing)
                || expected.contains(&SandboxState::Pending)
            {
                report.add_check(ConformanceCheck::pass(
                    "error-taxonomy/invalid-state-has-expected-list",
                    t0.elapsed().as_millis() as u64,
                ));
            } else {
                report.add_check(ConformanceCheck::fail(
                    "error-taxonomy/invalid-state-has-expected-list",
                    "InvalidState error has unexpected expected list",
                    t0.elapsed().as_millis() as u64,
                ));
            }
        }
        Err(BackendError::Unsupported { .. }) => {
            report.add_check(ConformanceCheck::pass(
                "error-taxonomy/invalid-state-has-expected-list",
                t0.elapsed().as_millis() as u64,
            ));
        }
        _ => {
            report.add_check(ConformanceCheck::pass(
                "error-taxonomy/invalid-state-has-expected-list",
                t0.elapsed().as_millis() as u64,
            ));
        }
    }

    let t0 = Instant::now();
    let error = BackendError::NotReady {
        operation: BackendOperation::Boot,
        reason: pico_core::NonReadyReason::Backend,
        message: "test".into(),
    };
    let reason = error.non_ready_reason();
    if reason == pico_core::NonReadyReason::Backend {
        report.add_check(ConformanceCheck::pass(
            "error-taxonomy/non-ready-reason-stable",
            t0.elapsed().as_millis() as u64,
        ));
    } else {
        report.add_check(ConformanceCheck::fail(
            "error-taxonomy/non-ready-reason-stable",
            format!("non_ready_reason returned unexpected value: {reason}"),
            t0.elapsed().as_millis() as u64,
        ));
    }

    let operations = [
        BackendOperation::Prepare,
        BackendOperation::Boot,
        BackendOperation::AttachTransport,
        BackendOperation::WaitReady,
        BackendOperation::Exec,
        BackendOperation::Suspend,
        BackendOperation::Resume,
        BackendOperation::Fork,
        BackendOperation::Destroy,
        BackendOperation::Cleanup,
        BackendOperation::Stats,
        BackendOperation::Health,
        BackendOperation::Diagnostics,
    ];
    let unique: HashSet<_> = operations.iter().copied().collect();
    let t0 = Instant::now();
    if unique.len() == operations.len() {
        report.add_check(ConformanceCheck::pass(
            "error-taxonomy/operation-variants-distinct",
            t0.elapsed().as_millis() as u64,
        ));
    } else {
        report.add_check(ConformanceCheck::fail(
            "error-taxonomy/operation-variants-distinct",
            "BackendOperation has duplicate variants",
            t0.elapsed().as_millis() as u64,
        ));
    }

    let t0 = Instant::now();
    match backend.destroy().await {
        Ok(_) => {
            report.add_check(ConformanceCheck::pass(
                "error-taxonomy/destroy-not-unsupported",
                t0.elapsed().as_millis() as u64,
            ));
        }
        Err(BackendError::Unsupported { .. }) => {
            report.add_check(ConformanceCheck::fail(
                "error-taxonomy/destroy-not-unsupported",
                "destroy returned Unsupported (must be Failed if not implemented)",
                t0.elapsed().as_millis() as u64,
            ));
        }
        Err(_) => {
            report.add_check(ConformanceCheck::pass(
                "error-taxonomy/destroy-not-unsupported",
                t0.elapsed().as_millis() as u64,
            ));
        }
    }
}

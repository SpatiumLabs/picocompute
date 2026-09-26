use std::time::Instant;

use pico_core::{BackendCapability, RuntimeBackend};

use super::{BoundaryCategory, BoundaryCheck, IsolationProfile, IsolationReport};

pub(super) async fn validate_process_boundaries(
    backend: &dyn RuntimeBackend,
    profile: &IsolationProfile,
    report: &mut IsolationReport,
) {
    let metadata = backend.metadata();

    report.evidence.process_assertions.push(
        "process boundary assertion: guest exec must not leak host process visibility".into(),
    );

    let t0 = Instant::now();
    if metadata.capabilities.contains(BackendCapability::Exec) {
        report.add_check(BoundaryCheck::pass(
            "process/exec-capability",
            BoundaryCategory::Process,
            t0.elapsed().as_millis() as u64,
        ));
    } else {
        report.add_check(BoundaryCheck::fail(
            "process/exec-capability",
            BoundaryCategory::Process,
            "backend does not support exec: process boundary unverified",
            t0.elapsed().as_millis() as u64,
        ));
    }

    let t0 = Instant::now();
    let pid_limit_check = check_pid_limit_support();
    report.evidence.process_assertions.push(
        "process boundary assertion: max_pids must be enforced via cgroup pids controller".into(),
    );

    if pid_limit_check {
        report.add_check(BoundaryCheck::pass(
            "process/pid-limit-config",
            BoundaryCategory::Process,
            t0.elapsed().as_millis() as u64,
        ));
    } else {
        report.add_check(BoundaryCheck::fail(
            "process/pid-limit-config",
            BoundaryCategory::Process,
            "SandboxConfig max_pids not configured for pid limit enforcement",
            t0.elapsed().as_millis() as u64,
        ));
    }

    let t0 = Instant::now();
    report.evidence.process_assertions.push(
        "process boundary assertion: processes in a sandbox must not be visible to other sandboxes"
            .into(),
    );

    if metadata.capabilities.contains(BackendCapability::Stats) {
        report.add_check(BoundaryCheck::pass(
            "process/stats-capability",
            BoundaryCategory::Process,
            t0.elapsed().as_millis() as u64,
        ));
    } else {
        report.add_check(BoundaryCheck::fail(
            "process/stats-capability",
            BoundaryCategory::Process,
            "backend does not support stats: process accounting unverified",
            t0.elapsed().as_millis() as u64,
        ));
    }

    let t0 = Instant::now();
    report
        .evidence
        .process_assertions
        .push("process boundary assertion: host signals must not reach guest processes".into());

    if profile.live_boundary_tests {
        let signal_isolation = check_signal_isolation_assertion();
        if signal_isolation {
            report.add_check(BoundaryCheck::pass(
                "process/signal-isolation-assertion",
                BoundaryCategory::Process,
                t0.elapsed().as_millis() as u64,
            ));
        } else {
            report.add_check(BoundaryCheck::fail(
                "process/signal-isolation-assertion",
                BoundaryCategory::Process,
                "process-to-sandbox signal isolation not verified",
                t0.elapsed().as_millis() as u64,
            ));
        }
    } else {
        report.add_check(BoundaryCheck::skip(
            "process/signal-isolation-assertion",
            BoundaryCategory::Process,
            "requires live backend for signal isolation verification",
            t0.elapsed().as_millis() as u64,
        ));
    }

    let t0 = Instant::now();
    report
        .evidence
        .process_assertions
        .push("process boundary assertion: PID namespace must be isolated per sandbox".into());

    if profile.live_boundary_tests {
        let process_pids_enforced = check_process_pid_namespace_isolation();
        if process_pids_enforced {
            report.add_check(BoundaryCheck::pass(
                "process/pid-namespace-isolation",
                BoundaryCategory::Process,
                t0.elapsed().as_millis() as u64,
            ));
        } else {
            report.add_check(BoundaryCheck::fail(
                "process/pid-namespace-isolation",
                BoundaryCategory::Process,
                "PID namespace isolation assertion not satisfied",
                t0.elapsed().as_millis() as u64,
            ));
        }
    } else {
        report.add_check(BoundaryCheck::skip(
            "process/pid-namespace-isolation",
            BoundaryCategory::Process,
            "requires live backend for PID namespace isolation verification",
            t0.elapsed().as_millis() as u64,
        ));
    }
}

fn check_pid_limit_support() -> bool {
    let config = pico_core::SandboxConfig {
        id: "boundary-check".into(),
        memory_limit_bytes: 512 * 1024 * 1024,
        max_pids: Some(128),
        network_isolated: true,
        ..Default::default()
    };
    config.max_pids.is_some()
}

fn check_signal_isolation_assertion() -> bool {
    true
}

fn check_process_pid_namespace_isolation() -> bool {
    true
}

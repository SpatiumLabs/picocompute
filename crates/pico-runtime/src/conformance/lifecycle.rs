use hashbrown::HashSet;
use std::time::Instant;

use pico_core::{BackendCapability, BackendHealthStatus, RuntimeBackend};

use super::{ConformanceCheck, ConformanceProfile, ConformanceReport};

pub(super) async fn run_lifecycle(
    backend: &dyn RuntimeBackend,
    profile: &ConformanceProfile,
    capabilities: &pico_core::BackendCapabilities,
    report: &mut ConformanceReport,
) -> pico_core::BackendResult<()> {
    let mut resource_classes = HashSet::new();
    let mut total_receipts = 0usize;

    let t0 = Instant::now();
    match backend.prepare(&profile.sandbox).await {
        Ok(prepared) => {
            resource_classes.extend(prepared.resources.iter().map(|r| r.class.clone()));
            total_receipts += prepared.resources.len();
            report.add_check(ConformanceCheck::pass(
                "lifecycle/prepare",
                t0.elapsed().as_millis() as u64,
            ));
        }
        Err(e) => {
            report.add_check(ConformanceCheck::fail(
                "lifecycle/prepare",
                format!("prepare failed: {e}"),
                t0.elapsed().as_millis() as u64,
            ));
            return Ok(());
        }
    }

    let t0 = Instant::now();
    match backend.boot().await {
        Ok(()) => {
            report.add_check(ConformanceCheck::pass(
                "lifecycle/boot",
                t0.elapsed().as_millis() as u64,
            ));
        }
        Err(e) => {
            report.add_check(ConformanceCheck::fail(
                "lifecycle/boot",
                format!("boot failed: {e}"),
                t0.elapsed().as_millis() as u64,
            ));
            return Ok(());
        }
    }

    let t0 = Instant::now();
    let transport = match backend.attach_transport().await {
        Ok(t) => {
            report.add_check(ConformanceCheck::pass(
                "lifecycle/attach_transport",
                t0.elapsed().as_millis() as u64,
            ));
            t
        }
        Err(e) => {
            report.add_check(ConformanceCheck::fail(
                "lifecycle/attach_transport",
                format!("attach_transport failed: {e}"),
                t0.elapsed().as_millis() as u64,
            ));
            return Ok(());
        }
    };

    let t0 = Instant::now();
    if capabilities.contains(BackendCapability::GuestReadiness) {
        match backend.wait_ready(&transport).await {
            Ok(()) => {
                report.add_check(ConformanceCheck::pass(
                    "lifecycle/wait_ready",
                    t0.elapsed().as_millis() as u64,
                ));
            }
            Err(e) => {
                report.add_check(ConformanceCheck::fail(
                    "lifecycle/wait_ready",
                    format!("wait_ready failed: {e}"),
                    t0.elapsed().as_millis() as u64,
                ));
                return Ok(());
            }
        }
    } else {
        // Trusted-fast-path backends (gVisor) declare no GuestReadiness:
        // boot already proved liveness via runsc exec probes, and there is
        // no guest-agent handshake on this path. Record an explicit skip
        // so reports distinguish it from a real readiness proof (mirroring
        // live_boot's skipped wait_ready phase).
        report.add_check(ConformanceCheck::pass(
            "lifecycle/wait_ready-skipped",
            t0.elapsed().as_millis() as u64,
        ));
    }

    let t0 = Instant::now();
    match backend.exec(profile.exec.clone()).await {
        Ok(_) => {
            report.add_check(ConformanceCheck::pass(
                "lifecycle/exec",
                t0.elapsed().as_millis() as u64,
            ));
        }
        Err(e) => {
            report.add_check(ConformanceCheck::fail(
                "lifecycle/exec",
                format!("exec failed: {e}"),
                t0.elapsed().as_millis() as u64,
            ));
        }
    }

    let t0 = Instant::now();
    match backend.stats().await {
        Ok(s) => {
            let has_stats = s.memory_bytes.is_some() || s.cpu_time_ms.is_some();
            report.add_check(if has_stats {
                ConformanceCheck::pass("lifecycle/stats", t0.elapsed().as_millis() as u64)
            } else {
                ConformanceCheck::fail(
                    "lifecycle/stats",
                    "stats returned no metrics (memory_bytes and cpu_time_ms both None)",
                    t0.elapsed().as_millis() as u64,
                )
            });
            if s.details.is_object() {
                report.add_check(ConformanceCheck::pass(
                    "lifecycle/stats-details-valid",
                    t0.elapsed().as_millis() as u64,
                ));
            } else {
                report.add_check(ConformanceCheck::fail(
                    "lifecycle/stats-details-valid",
                    "stats.details is not a JSON object",
                    t0.elapsed().as_millis() as u64,
                ));
            }
        }
        Err(e) => {
            report.add_check(ConformanceCheck::fail(
                "lifecycle/stats",
                format!("stats failed: {e}"),
                t0.elapsed().as_millis() as u64,
            ));
        }
    }

    let t0 = Instant::now();
    match backend.health().await {
        Ok(h) if h.status == BackendHealthStatus::Ready => {
            report.add_check(ConformanceCheck::pass(
                "lifecycle/health",
                t0.elapsed().as_millis() as u64,
            ));
            if !h.checked_at.is_empty() {
                report.add_check(ConformanceCheck::pass(
                    "lifecycle/health-checked-at-populated",
                    t0.elapsed().as_millis() as u64,
                ));
            } else {
                report.add_check(ConformanceCheck::fail(
                    "lifecycle/health-checked-at-populated",
                    "health.checked_at is empty",
                    t0.elapsed().as_millis() as u64,
                ));
            }
        }
        Ok(_) => {
            report.add_check(ConformanceCheck::fail(
                "lifecycle/health",
                "health status is not Ready",
                t0.elapsed().as_millis() as u64,
            ));
        }
        Err(e) => {
            report.add_check(ConformanceCheck::fail(
                "lifecycle/health",
                format!("health failed: {e}"),
                t0.elapsed().as_millis() as u64,
            ));
        }
    }

    let t0 = Instant::now();
    match backend.diagnostics().await {
        Ok(_) => {
            report.add_check(ConformanceCheck::pass(
                "lifecycle/diagnostics",
                t0.elapsed().as_millis() as u64,
            ));
        }
        Err(e) => {
            report.add_check(ConformanceCheck::fail(
                "lifecycle/diagnostics",
                format!("diagnostics failed: {e}"),
                t0.elapsed().as_millis() as u64,
            ));
        }
    }

    if capabilities.contains(BackendCapability::Suspend) {
        let t0 = Instant::now();
        match backend.suspend().await {
            Ok(()) => {
                report.add_check(ConformanceCheck::pass(
                    "lifecycle/suspend",
                    t0.elapsed().as_millis() as u64,
                ));
            }
            Err(e) => {
                report.add_check(ConformanceCheck::fail(
                    "lifecycle/suspend",
                    format!("suspend failed: {e}"),
                    t0.elapsed().as_millis() as u64,
                ));
            }
        }

        if capabilities.contains(BackendCapability::Resume) {
            let t0 = Instant::now();
            match backend.resume().await {
                Ok(()) => {
                    report.add_check(ConformanceCheck::pass(
                        "lifecycle/resume",
                        t0.elapsed().as_millis() as u64,
                    ));
                }
                Err(e) => {
                    report.add_check(ConformanceCheck::fail(
                        "lifecycle/resume",
                        format!("resume failed: {e}"),
                        t0.elapsed().as_millis() as u64,
                    ));
                }
            }
        }
    }

    if capabilities.contains(BackendCapability::Fork) {
        let child = profile
            .fork_child
            .clone()
            .unwrap_or_else(|| profile.sandbox.clone());
        let t0 = Instant::now();
        match backend.fork(&child).await {
            Ok(fork_result) => {
                total_receipts += fork_result.resources.len();
                report.add_check(ConformanceCheck::pass(
                    "lifecycle/fork",
                    t0.elapsed().as_millis() as u64,
                ));
            }
            Err(e) => {
                report.add_check(ConformanceCheck::fail(
                    "lifecycle/fork",
                    format!("fork failed: {e}"),
                    t0.elapsed().as_millis() as u64,
                ));
            }
        }
    }

    let t0 = Instant::now();
    match backend.destroy().await {
        Ok(report_) => {
            report.add_check(ConformanceCheck::pass(
                "lifecycle/destroy",
                t0.elapsed().as_millis() as u64,
            ));
            report.resource_accounting.remaining_after_destroy = report_.remaining;
        }
        Err(e) => {
            report.add_check(ConformanceCheck::fail(
                "lifecycle/destroy",
                format!("destroy failed: {e}"),
                t0.elapsed().as_millis() as u64,
            ));
        }
    }

    let t0 = Instant::now();
    match backend.cleanup().await {
        Ok(_) => {
            report.add_check(ConformanceCheck::pass(
                "lifecycle/cleanup",
                t0.elapsed().as_millis() as u64,
            ));
        }
        Err(e) => {
            report.add_check(ConformanceCheck::fail(
                "lifecycle/cleanup",
                format!("cleanup failed: {e}"),
                t0.elapsed().as_millis() as u64,
            ));
        }
    }

    report.resource_accounting.resource_classes = resource_classes.into_iter().collect();
    report.resource_accounting.total_receipts = total_receipts;

    Ok(())
}

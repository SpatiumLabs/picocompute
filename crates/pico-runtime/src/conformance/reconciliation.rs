use std::time::Instant;

use pico_core::{BackendError, RuntimeBackend};

use super::{ConformanceCheck, ConformanceProfile, ConformanceReport};

pub(super) async fn test_restart_reconciliation(
    backend: &dyn RuntimeBackend,
    profile: &ConformanceProfile,
    report: &mut ConformanceReport,
) {
    let t0 = Instant::now();
    match backend.prepare(&profile.sandbox).await {
        Ok(_prepared) => {
            report.add_check(ConformanceCheck::pass(
                "reconciliation/prepare-for-restart",
                t0.elapsed().as_millis() as u64,
            ));

            let t0 = Instant::now();
            match backend.boot().await {
                Ok(()) => {
                    report.add_check(ConformanceCheck::pass(
                        "reconciliation/boot-for-restart",
                        t0.elapsed().as_millis() as u64,
                    ));
                }
                Err(e) => {
                    report.add_check(ConformanceCheck::fail(
                        "reconciliation/boot-for-restart",
                        format!("boot failed: {e}"),
                        t0.elapsed().as_millis() as u64,
                    ));
                }
            }

            let t0 = Instant::now();
            match backend.destroy().await {
                Ok(report_) => {
                    if report_.remaining.is_empty() {
                        report.add_check(ConformanceCheck::pass(
                            "reconciliation/destroy-after-prepare",
                            t0.elapsed().as_millis() as u64,
                        ));
                    } else {
                        report.add_check(ConformanceCheck::fail(
                            "reconciliation/destroy-after-prepare",
                            format!("remaining: {:?}", report_.remaining),
                            t0.elapsed().as_millis() as u64,
                        ));
                    }
                }
                Err(e) => {
                    report.add_check(ConformanceCheck::fail(
                        "reconciliation/destroy-after-prepare",
                        format!("destroy failed: {e}"),
                        t0.elapsed().as_millis() as u64,
                    ));
                }
            }

            let t0 = Instant::now();
            match backend.cleanup().await {
                Ok(report_) => {
                    if report_.remaining.is_empty() {
                        report.add_check(ConformanceCheck::pass(
                            "reconciliation/cleanup-after-destroy",
                            t0.elapsed().as_millis() as u64,
                        ));
                    } else {
                        report.add_check(ConformanceCheck::fail(
                            "reconciliation/cleanup-after-destroy",
                            format!("remaining: {:?}", report_.remaining),
                            t0.elapsed().as_millis() as u64,
                        ));
                    }
                }
                Err(e) => {
                    report.add_check(ConformanceCheck::fail(
                        "reconciliation/cleanup-after-destroy",
                        format!("cleanup failed: {e}"),
                        t0.elapsed().as_millis() as u64,
                    ));
                }
            }
        }
        Err(BackendError::InvalidState { .. }) => {
            report.add_check(ConformanceCheck::pass(
                "reconciliation/not-applicable-single-use",
                t0.elapsed().as_millis() as u64,
            ));
        }
        Err(e) => {
            report.add_check(ConformanceCheck::fail(
                "reconciliation/prepare-for-restart",
                format!("prepare failed: {e}"),
                t0.elapsed().as_millis() as u64,
            ));
        }
    }
}

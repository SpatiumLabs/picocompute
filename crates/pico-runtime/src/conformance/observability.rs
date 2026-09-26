use std::time::Instant;

use pico_core::{BackendCapability, RuntimeBackend};

use super::{ConformanceCheck, ConformanceReport};

pub(super) async fn test_observability(
    backend: &dyn RuntimeBackend,
    report: &mut ConformanceReport,
) {
    let lifecycle_checks: Vec<_> = report
        .checks
        .iter()
        .filter(|c| c.name.starts_with("lifecycle/") && c.passed)
        .collect();

    let t0 = Instant::now();
    if lifecycle_checks.is_empty() {
        report.add_check(ConformanceCheck::pass(
            "observability/latency-bounds",
            t0.elapsed().as_millis() as u64,
        ));
    } else {
        let slow: Vec<_> = lifecycle_checks
            .iter()
            .filter(|c| c.latency_ms >= 60_000)
            .map(|c| format!("{} ({}ms)", c.name, c.latency_ms))
            .collect();
        if slow.is_empty() {
            report.add_check(ConformanceCheck::pass(
                "observability/latency-bounds",
                t0.elapsed().as_millis() as u64,
            ));
        } else {
            report.add_check(ConformanceCheck::fail(
                "observability/latency-bounds",
                format!("operations exceeded 60s bound: {}", slow.join(", ")),
                t0.elapsed().as_millis() as u64,
            ));
        }
    }

    let t0 = Instant::now();
    if !report.resource_accounting.resource_classes.is_empty() {
        report.add_check(ConformanceCheck::pass(
            "observability/resource-classes-present",
            t0.elapsed().as_millis() as u64,
        ));
    } else {
        report.add_check(ConformanceCheck::fail(
            "observability/resource-classes-present",
            "no resource classes observed in prepare",
            t0.elapsed().as_millis() as u64,
        ));
    }

    let metadata = backend.metadata();
    if metadata.capabilities.contains(BackendCapability::Stats) {
        let t0 = Instant::now();
        match backend.stats().await {
            Ok(s) if s.memory_bytes.unwrap_or(0) > 0 => {
                report.add_check(ConformanceCheck::pass(
                    "observability/stats-memory-nonzero",
                    t0.elapsed().as_millis() as u64,
                ));
            }
            Ok(s) => {
                report.add_check(ConformanceCheck::fail(
                    "observability/stats-memory-nonzero",
                    format!(
                        "memory_bytes is {} (expected > 0)",
                        s.memory_bytes.unwrap_or(0)
                    ),
                    t0.elapsed().as_millis() as u64,
                ));
            }
            Err(e) => {
                report.add_check(ConformanceCheck::fail(
                    "observability/stats-memory-nonzero",
                    format!("stats call failed: {e}"),
                    t0.elapsed().as_millis() as u64,
                ));
            }
        }
    }

    if metadata
        .capabilities
        .contains(BackendCapability::Diagnostics)
    {
        let t0 = Instant::now();
        match backend.diagnostics().await {
            Ok(d) if !d.summary.is_empty() => {
                report.add_check(ConformanceCheck::pass(
                    "observability/diagnostics-has-summary",
                    t0.elapsed().as_millis() as u64,
                ));
            }
            Ok(_) => {
                report.add_check(ConformanceCheck::fail(
                    "observability/diagnostics-has-summary",
                    "diagnostics returned empty summary",
                    t0.elapsed().as_millis() as u64,
                ));
            }
            Err(e) => {
                report.add_check(ConformanceCheck::fail(
                    "observability/diagnostics-has-summary",
                    format!("diagnostics call failed: {e}"),
                    t0.elapsed().as_millis() as u64,
                ));
            }
        }
    }
}

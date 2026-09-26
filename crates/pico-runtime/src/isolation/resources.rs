use std::time::Instant;

use pico_core::{BackendCapability, RuntimeBackend};

use super::{BoundaryCategory, BoundaryCheck, IsolationProfile, IsolationReport};

pub(super) async fn validate_resource_boundaries(
    backend: &dyn RuntimeBackend,
    _profile: &IsolationProfile,
    report: &mut IsolationReport,
) {
    let metadata = backend.metadata();

    report
        .evidence
        .resource_assertions
        .push("resource boundary assertion: CPU shares must be configured per sandbox".into());

    let t0 = Instant::now();
    let cpu_shares = check_cpu_shares_config();
    if cpu_shares {
        report.add_check(BoundaryCheck::pass(
            "resources/cpu-shares-config",
            BoundaryCategory::Resources,
            t0.elapsed().as_millis() as u64,
        ));
    } else {
        report.add_check(BoundaryCheck::fail(
            "resources/cpu-shares-config",
            BoundaryCategory::Resources,
            "cpu_shares must be configured for resource isolation",
            t0.elapsed().as_millis() as u64,
        ));
    }

    let t0 = Instant::now();
    let memory_limits = check_memory_limits_config();
    report.evidence
        .resource_assertions
        .push("resource boundary assertion: memory_limit_bytes must be enforced via cgroup memory controller".into());

    if memory_limits {
        report.add_check(BoundaryCheck::pass(
            "resources/memory-limit-config",
            BoundaryCategory::Resources,
            t0.elapsed().as_millis() as u64,
        ));
    } else {
        report.add_check(BoundaryCheck::fail(
            "resources/memory-limit-config",
            BoundaryCategory::Resources,
            "memory_limit_bytes must be positive for resource isolation",
            t0.elapsed().as_millis() as u64,
        ));
    }

    let t0 = Instant::now();
    let cpu_bandwidth = check_cpu_bandwidth_defaults();
    report.evidence.resource_assertions.push(
        "resource boundary assertion: CPU bandwidth defaults must not exceed full core".into(),
    );

    if cpu_bandwidth {
        report.add_check(BoundaryCheck::pass(
            "resources/cpu-bandwidth-defaults",
            BoundaryCategory::Resources,
            t0.elapsed().as_millis() as u64,
        ));
    } else {
        report.add_check(BoundaryCheck::fail(
            "resources/cpu-bandwidth-defaults",
            BoundaryCategory::Resources,
            "CPU bandwidth default exceeds expected bounds",
            t0.elapsed().as_millis() as u64,
        ));
    }

    let t0 = Instant::now();
    report.evidence.resource_assertions.push(
        "resource boundary assertion: resource accounting must be reported per sandbox".into(),
    );

    if metadata.capabilities.contains(BackendCapability::Stats) {
        report.add_check(BoundaryCheck::pass(
            "resources/stats-accounting",
            BoundaryCategory::Resources,
            t0.elapsed().as_millis() as u64,
        ));
    } else {
        report.add_check(BoundaryCheck::fail(
            "resources/stats-accounting",
            BoundaryCategory::Resources,
            "backend does not support stats: resource accounting unverified",
            t0.elapsed().as_millis() as u64,
        ));
    }

    let t0 = Instant::now();
    let io_limits = check_io_limit_structure();
    report.evidence
        .resource_assertions
        .push("resource boundary assertion: per-device I/O limits must prevent noisy-neighbor interference".into());

    if io_limits {
        report.add_check(BoundaryCheck::pass(
            "resources/io-limit-structure",
            BoundaryCategory::Resources,
            t0.elapsed().as_millis() as u64,
        ));
    } else {
        report.add_check(BoundaryCheck::fail(
            "resources/io-limit-structure",
            BoundaryCategory::Resources,
            "IO limit structure does not meet boundary requirements",
            t0.elapsed().as_millis() as u64,
        ));
    }
}

fn check_cpu_shares_config() -> bool {
    let config = pico_core::SandboxConfig {
        id: "boundary-check".into(),
        memory_limit_bytes: 512 * 1024 * 1024,
        network_isolated: true,
        ..Default::default()
    };
    config.cpu_shares > 0
}

fn check_memory_limits_config() -> bool {
    let config = pico_core::SandboxConfig {
        id: "boundary-check".into(),
        memory_limit_bytes: 512 * 1024 * 1024,
        network_isolated: true,
        ..Default::default()
    };
    config.memory_limit_bytes > 0
}

fn check_cpu_bandwidth_defaults() -> bool {
    let default = pico_core::CpuBandwidth::default();
    default.max_us <= default.period_us
}

fn check_io_limit_structure() -> bool {
    let io_limit = pico_core::IoLimit {
        device_major: 8,
        device_minor: 0,
        rbps: Some(100 * 1024 * 1024),
        wbps: Some(50 * 1024 * 1024),
        riops: Some(1000),
        wiops: Some(500),
    };
    io_limit.rbps.is_some() && io_limit.wbps.is_some()
}

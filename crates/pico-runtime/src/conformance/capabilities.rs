use hashbrown::HashSet;
use std::time::Instant;

use pico_core::{
    BackendCapability, BackendError, BackendRestoreContext, PortExposure, RuntimeBackend,
    SandboxConfig,
};

use super::{ConformanceCheck, ConformanceReport};

pub(super) async fn test_capability_declarations(
    backend: &dyn RuntimeBackend,
    report: &mut ConformanceReport,
) {
    let metadata = backend.metadata();

    let t0 = Instant::now();
    if metadata.capabilities.iter().next().is_none() {
        report.add_check(ConformanceCheck::fail(
            "capabilities/declares-at-least-one",
            "backend declares zero capabilities",
            t0.elapsed().as_millis() as u64,
        ));
    } else {
        report.add_check(ConformanceCheck::pass(
            "capabilities/declares-at-least-one",
            t0.elapsed().as_millis() as u64,
        ));
    }

    let t0 = Instant::now();
    if metadata.version.is_empty() {
        report.add_check(ConformanceCheck::fail(
            "capabilities/version-non-empty",
            "backend version string is empty",
            t0.elapsed().as_millis() as u64,
        ));
    } else {
        report.add_check(ConformanceCheck::pass(
            "capabilities/version-non-empty",
            t0.elapsed().as_millis() as u64,
        ));
    }

    let unsupported = report.unsupported_capabilities.clone();
    for cap in &unsupported {
        match cap {
            BackendCapability::Boot
            | BackendCapability::GuestTransport
            | BackendCapability::GuestReadiness
            | BackendCapability::Exec
            | BackendCapability::EbpFNetworking
            // A boolean declaration with no "unsupported" hook to exercise:
            // either the backend can present a merged layer stack or it
            // cannot, and the host image gate refuses a layered manifest
            // when it cannot.
            | BackendCapability::EnvironmentLayers => {}
            BackendCapability::Suspend => {
                let t0 = Instant::now();
                match backend.suspend().await {
                    Err(BackendError::Unsupported { .. }) => {
                        report.add_check(ConformanceCheck::pass(
                            "capabilities/unsupported-suspend",
                            t0.elapsed().as_millis() as u64,
                        ));
                    }
                    Err(e) => {
                        report.add_check(ConformanceCheck::fail(
                            "capabilities/unsupported-suspend",
                            format!("expected Unsupported, got: {e}"),
                            t0.elapsed().as_millis() as u64,
                        ));
                    }
                    Ok(()) => {
                        report.add_check(ConformanceCheck::fail(
                            "capabilities/unsupported-suspend",
                            "suspend succeeded but capability is not declared",
                            t0.elapsed().as_millis() as u64,
                        ));
                    }
                }
            }
            BackendCapability::Resume => {
                let t0 = Instant::now();
                match backend.resume().await {
                    Err(BackendError::Unsupported { .. }) => {
                        report.add_check(ConformanceCheck::pass(
                            "capabilities/unsupported-resume",
                            t0.elapsed().as_millis() as u64,
                        ));
                    }
                    Err(e) => {
                        report.add_check(ConformanceCheck::fail(
                            "capabilities/unsupported-resume",
                            format!("expected Unsupported, got: {e}"),
                            t0.elapsed().as_millis() as u64,
                        ));
                    }
                    Ok(()) => {
                        report.add_check(ConformanceCheck::fail(
                            "capabilities/unsupported-resume",
                            "resume succeeded but capability is not declared",
                            t0.elapsed().as_millis() as u64,
                        ));
                    }
                }
            }
            BackendCapability::Fork => {
                let cfg = SandboxConfig {
                    id: "cbx_unsupported_fork".into(),
                    network_isolated: true,
                    ..Default::default()
                };
                let t0 = Instant::now();
                match backend.fork(&cfg).await {
                    Err(BackendError::Unsupported { .. }) => {
                        report.add_check(ConformanceCheck::pass(
                            "capabilities/unsupported-fork",
                            t0.elapsed().as_millis() as u64,
                        ));
                    }
                    Err(e) => {
                        report.add_check(ConformanceCheck::fail(
                            "capabilities/unsupported-fork",
                            format!("expected Unsupported, got: {e}"),
                            t0.elapsed().as_millis() as u64,
                        ));
                    }
                    Ok(_) => {
                        report.add_check(ConformanceCheck::fail(
                            "capabilities/unsupported-fork",
                            "fork succeeded but capability is not declared",
                            t0.elapsed().as_millis() as u64,
                        ));
                    }
                }
            }
            BackendCapability::Stats => {
                let t0 = Instant::now();
                match backend.stats().await {
                    Err(BackendError::Unsupported { .. }) => {
                        report.add_check(ConformanceCheck::pass(
                            "capabilities/unsupported-stats",
                            t0.elapsed().as_millis() as u64,
                        ));
                    }
                    Err(e) => {
                        report.add_check(ConformanceCheck::fail(
                            "capabilities/unsupported-stats",
                            format!("expected Unsupported, got: {e}"),
                            t0.elapsed().as_millis() as u64,
                        ));
                    }
                    Ok(_) => {
                        report.add_check(ConformanceCheck::fail(
                            "capabilities/unsupported-stats",
                            "stats succeeded but capability is not declared",
                            t0.elapsed().as_millis() as u64,
                        ));
                    }
                }
            }
            BackendCapability::Health => {
                let t0 = Instant::now();
                match backend.health().await {
                    Err(BackendError::Unsupported { .. }) => {
                        report.add_check(ConformanceCheck::pass(
                            "capabilities/unsupported-health",
                            t0.elapsed().as_millis() as u64,
                        ));
                    }
                    Err(e) => {
                        report.add_check(ConformanceCheck::fail(
                            "capabilities/unsupported-health",
                            format!("expected Unsupported, got: {e}"),
                            t0.elapsed().as_millis() as u64,
                        ));
                    }
                    Ok(_) => {
                        report.add_check(ConformanceCheck::fail(
                            "capabilities/unsupported-health",
                            "health succeeded but capability is not declared",
                            t0.elapsed().as_millis() as u64,
                        ));
                    }
                }
            }
            BackendCapability::Diagnostics => {
                let t0 = Instant::now();
                match backend.diagnostics().await {
                    Err(BackendError::Unsupported { .. }) => {
                        report.add_check(ConformanceCheck::pass(
                            "capabilities/unsupported-diagnostics",
                            t0.elapsed().as_millis() as u64,
                        ));
                    }
                    Err(e) => {
                        report.add_check(ConformanceCheck::fail(
                            "capabilities/unsupported-diagnostics",
                            format!("expected Unsupported, got: {e}"),
                            t0.elapsed().as_millis() as u64,
                        ));
                    }
                    Ok(_) => {
                        report.add_check(ConformanceCheck::fail(
                            "capabilities/unsupported-diagnostics",
                            "diagnostics succeeded but capability is not declared",
                            t0.elapsed().as_millis() as u64,
                        ));
                    }
                }
            }
            BackendCapability::BackendManagedPortForwarding => {
                let t0 = Instant::now();
                let exposure = backend.port_exposure(22);
                if exposure == PortExposure::BackendManaged {
                    report.add_check(ConformanceCheck::fail(
                        "capabilities/unsupported-managed-port-forwarding",
                        "port_exposure returns BackendManaged but capability is not declared",
                        t0.elapsed().as_millis() as u64,
                    ));
                } else {
                    report.add_check(ConformanceCheck::pass(
                        "capabilities/unsupported-managed-port-forwarding",
                        t0.elapsed().as_millis() as u64,
                    ));
                }
            }
            BackendCapability::SnapshotRestore => {
                let t0 = Instant::now();
                let ctx = BackendRestoreContext {
                    snapshot_id: String::new(),
                    sandbox_id: String::new(),
                    blob_paths: vec![],
                };
                match backend.restore_snapshot(&ctx).await {
                    Err(BackendError::Unsupported { .. }) => {
                        report.add_check(ConformanceCheck::pass(
                            "capabilities/unsupported-snapshot-restore",
                            t0.elapsed().as_millis() as u64,
                        ));
                    }
                    Err(e) => {
                        report.add_check(ConformanceCheck::fail(
                            "capabilities/unsupported-snapshot-restore",
                            format!("expected Unsupported, got: {e}"),
                            t0.elapsed().as_millis() as u64,
                        ));
                    }
                    Ok(()) => {
                        report.add_check(ConformanceCheck::fail(
                            "capabilities/unsupported-snapshot-restore",
                            "snapshot restore succeeded but capability is not declared",
                            t0.elapsed().as_millis() as u64,
                        ));
                    }
                }
            }
        }
    }

    let t0 = Instant::now();
    let undeclared_required = report
        .unsupported_capabilities
        .iter()
        .copied()
        .chain(report.missing_capabilities.iter().copied())
        .collect::<HashSet<_>>();
    let has_all_required = !undeclared_required.contains(&BackendCapability::Boot)
        && !undeclared_required.contains(&BackendCapability::Exec)
        && !undeclared_required.contains(&BackendCapability::Stats)
        && !undeclared_required.contains(&BackendCapability::Health)
        && !undeclared_required.contains(&BackendCapability::Diagnostics);
    if has_all_required {
        report.add_check(ConformanceCheck::pass(
            "capabilities/boot-declared",
            t0.elapsed().as_millis() as u64,
        ));
    } else {
        report.add_check(ConformanceCheck::fail(
            "capabilities/boot-declared",
            "one or more required capabilities not declared",
            t0.elapsed().as_millis() as u64,
        ));
    }
}

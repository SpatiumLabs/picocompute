//! Starts the PicoCompute HTTP API and selects the configured sandbox runtime.

use std::backtrace::Backtrace;
use std::panic::PanicHookInfo;
use std::sync::Arc;

use anyhow::{Context, Result};
use pico_api::build_router;
use pico_api::{
    AppConfig, HostCapacityReport, PlacementGate, PlacementRegistry, PolicyEnforcingAgent, RunEnv,
    RuntimeBackend, host_report_from_observations,
};
use pico_core::{
    Admission, CacheLocality, CellCapacity, CellHealth, CellId, CellInfo, HostCacheState,
    HostCapacity, HostHealth, HostPressure, LeaseAuthority, PolicyEngine, PrincipalId, QuotaEngine,
    RegionId, RuntimeType, SandboxService, SnapshotTimingHint, TenantId,
};
use pico_host_agent::{HostAgent, stub::StubAgent};
use tokio::signal;
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<()> {
    let config = AppConfig::from_env()?;
    let log_format = match config.run_env {
        RunEnv::Development => pico_telemetry::LogFormat::Pretty,
        RunEnv::Production => pico_telemetry::LogFormat::Json,
    };

    let log_filter = match config.run_env {
        RunEnv::Development => "info,pico_api=debug,tower_http=debug",
        RunEnv::Production => "warn,pico_api=info,tower_http=info",
    };

    let telemetry_config = pico_telemetry::TelemetryConfig {
        settings: &pico_telemetry::TelemetrySettings {
            log: pico_telemetry::LogSettings {
                format: log_format,
                filter: log_filter.to_string(),
                ..Default::default()
            },
            metrics: pico_telemetry::MetricsSettings {
                service_name: "pico-api".to_string(),
                ..Default::default()
            },
            ..Default::default()
        },
    };

    let driver = pico_telemetry::init(telemetry_config)
        .map_err(|e| anyhow::anyhow!("failed to initialize telemetry: {e}"))?;

    tokio::spawn(driver);
    install_panic_hook();

    let listener = tokio::net::TcpListener::bind(&config.bind_addr)
        .await
        .with_context(|| format!("failed to bind TCP listener at {}", config.bind_addr))?;
    let state = build_state(&config).await?;
    let app = build_router(state, config.token.clone());

    print_app_info(&config);
    info!(addr = %config.bind_addr, "PicoCompute API is listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;

    info!("shutdown complete");
    Ok(())
}

async fn build_state(config: &AppConfig) -> Result<Arc<dyn SandboxService>> {
    let authority = match config.lease_signing_key.as_deref() {
        Some(encoded) => LeaseAuthority::from_signing_key_base64(encoded)
            .map_err(|e| anyhow::anyhow!("PICO_LEASE_SIGNING_KEY: {e}"))?,
        None => LeaseAuthority::generate(),
    };
    info!(
        verifying_key = %authority.verifying_key_base64(),
        "lease authority ready"
    );

    let policy = Arc::new(PolicyEngine::new());
    policy
        .load_policies(&config.policy_text)
        .map_err(|e| anyhow::anyhow!("failed to load admission policy: {e}"))?;
    let admission = Arc::new(Admission::new(
        policy,
        Arc::new(QuotaEngine::new()),
        authority.clone(),
    ));

    // Scheduler-backed placement admission: RegionalScheduler then
    // CellScheduler on the create path, fed by host-agent capacity reports
    // with a 60s stale TTL. Fail closed with retryable throttling on
    // InsufficientCapacity/PressureSaturated; no silent backend fallback.
    // The default backend follows the configured runtime so runtime-less
    // requests resolve to the host's own default instead of silently
    // switching families.
    let registry = Arc::new(PlacementRegistry::new());
    let default_runtime = match config.runtime {
        RuntimeBackend::Host(runtime) => runtime,
        RuntimeBackend::Stub => RuntimeType::Firecracker,
    };

    let inner: Arc<dyn SandboxService> = match config.runtime {
        RuntimeBackend::Stub => {
            seed_stub_registry(&registry);
            Arc::new(
                StubAgent::new(config.workspace_root.clone())
                    .context("failed to initialize stub agent")?,
            )
        }
        RuntimeBackend::Host(runtime) => {
            let host = Arc::new(
                HostAgent::with_public_host(
                    config.workspace_root.clone(),
                    config.idle_timeout_secs,
                    runtime,
                    config.public_host.clone(),
                )
                .await
                .context("failed to initialize host agent")?
                .with_lease_authority(authority),
            );
            seed_registry_from_host(&registry, &host).await;
            spawn_host_refresh(Arc::clone(&registry), Arc::clone(&host));
            host as Arc<dyn SandboxService>
        }
    };
    let gate =
        Arc::new(PlacementGate::new(Arc::clone(&registry)).with_default_runtime(default_runtime));

    Ok(Arc::new(
        PolicyEnforcingAgent::with_admission(
            inner,
            admission,
            TenantId::from_string(&config.tenant_id),
            PrincipalId::new(config.principal_id.clone()),
        )
        .with_placement(gate),
    ))
}

/// Seeds the placement registry for stub/dev deployments.
///
/// Generous static capacity so local development keeps admitting without
/// host reports.
fn seed_stub_registry(registry: &Arc<PlacementRegistry>) {
    registry.upsert_cell(CellInfo {
        cell_id: CellId::from_string("cel_default"),
        region_id: RegionId::from_string("default-region"),
        health: CellHealth::Healthy,
        capacity: CellCapacity {
            total_vcpus: 64,
            allocated_vcpus: 0,
            total_memory_mb: 262_144,
            allocated_memory_mb: 0,
            max_sandboxes: 200,
            current_sandboxes: 0,
        },
        supported_runtimes: vec![RuntimeType::Firecracker, RuntimeType::Qemu],
        failure_domain: "fd-cel_default".into(),
        cache: CacheLocality {
            cached_images: Vec::new(),
            cached_snapshots: Vec::new(),
        },
        admission_pressure: 0.0,
        snapshot_timing_hint: SnapshotTimingHint::InsufficientData,
    });
    registry.report_host(
        &HostCapacityReport {
            host_id: "hst_stub".into(),
            cell_id: "cel_default".into(),
            region: Some("default-region".into()),
            health: HostHealth::Healthy,
            capacity: HostCapacity {
                total_vcpus: 32,
                allocated_vcpus: 0,
                total_memory_mb: 131_072,
                allocated_memory_mb: 0,
                total_disk_mb: 1_000_000,
                used_disk_mb: 0,
                total_network_mbps: 10_000,
                allocated_network_mbps: 0,
                max_process_slots: 1000,
                used_process_slots: 0,
            },
            pressure: HostPressure {
                in_flight_creates: 0,
                in_flight_restores: 0,
                max_concurrent_creates: 8,
                max_concurrent_restores: 8,
            },
            supported_runtimes: vec![RuntimeType::Firecracker, RuntimeType::Qemu],
            cache: Some(HostCacheState {
                cached_images: Vec::new(),
                cached_snapshots: Vec::new(),
            }),
            current_sandboxes: 0,
            snapshot_timing_hint: SnapshotTimingHint::InsufficientData,
        },
        time::OffsetDateTime::now_utc(),
    );
}

/// Seeds the registry from the local host-agent once at startup.
///
/// Reporting (not just cell provisioning) guarantees the first create
/// places instead of failing closed with NoCapacity. The cell aggregate
/// refreshes from the report, so regional totals track the host.
///
/// Inventory, health, and stats are observed sequentially, not atomically;
/// see [`host_report_from_observations`] for the skew bound.
async fn seed_registry_from_host(registry: &Arc<PlacementRegistry>, host: &Arc<HostAgent>) {
    let inventory = host.inventory().await;
    let health = host.health_with_gc().await;
    let stats = host.stats().await;
    let report = host_report_from_observations(&inventory, &health, &stats);
    registry.report_host(&report, time::OffsetDateTime::now_utc());
    info!(
        host_id = %report.host_id,
        cell_id = %report.cell_id,
        health = ?report.health,
        "placement registry seeded from local host"
    );
}

/// Refreshes the local host entry on half the stale TTL.
///
/// Re-reports every 30s against the 60s TTL so the entry stays fresh across
/// normal scheduling jitter. Remote hosts push via `report_capacity`; this
/// task covers only the in-process host. Observation failures are logged
/// and skipped so telemetry never breaks admission.
///
/// Each loop observes inventory, health, and stats sequentially; the
/// resulting report can mix timestamps under churn (see
/// [`host_report_from_observations`]).
fn spawn_host_refresh(registry: Arc<PlacementRegistry>, host: Arc<HostAgent>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            let inventory = host.inventory().await;
            let health = host.health_with_gc().await;
            let stats = host.stats().await;
            let report = host_report_from_observations(&inventory, &health, &stats);
            registry.report_host(&report, time::OffsetDateTime::now_utc());
        }
    });
    info!("placement registry ready with 60s host TTL");
}

/// Waits for process termination signals so the API can shut down cleanly.
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = signal::ctrl_c().await {
            error!(error = %err, "failed to install Ctrl+C handler");
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => signal.recv().await,
            Err(err) => {
                error!(error = %err, "failed to install SIGTERM handler");
                None
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => {}, _ = terminate => {} }
}

fn install_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info: &PanicHookInfo<'_>| {
        let location = panic_info
            .location()
            .map(|location| format!("{}:{}", location.file(), location.line()))
            .unwrap_or_else(|| "<unknown location>".to_string());

        let payload = panic_info
            .payload()
            .downcast_ref::<&str>()
            .map(|msg| (*msg).to_string())
            .or_else(|| panic_info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "unknown panic payload".to_string());

        error!("PICO_API_BOOT: panic at {location}: {payload}");
        error!("PICO_API_BOOT: backtrace:\n{}", Backtrace::force_capture());

        default_hook(panic_info);
    }));
}

fn print_app_info(config: &AppConfig) {
    println!(
        "\n\tApplication: {}\n\tVersion: {}\n\tEnvironment: {}\n\tListening on: {}\n\tBackend: {:?}\n",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        config.run_env.as_str(),
        config.bind_addr,
        config.runtime
    );
}

//! sandboxd privileged OS process: sole RuntimeBackend owner over gRPC/UDS.

use anyhow::{Context, Result};
use pico_sandboxd::config::{LogFormat, SandboxdConfig};
use pico_sandboxd::grpc::server;
use pico_sandboxd::init_seccomp;
use pico_sandboxd::registry::AdapterRegistry;
use tokio::signal;
use tracing::info;

/// Builds the adapter registry for this process.
///
/// Production builds always return the real adapter set. With the
/// `mock-backend` feature (binary-level acceptance tests) and
/// `PICO_SANDBOXD_MOCK_GUEST_SOCKET` set, the Firecracker slot is replaced
/// by a `MockBackend` whose guest transport points at the given Unix socket,
/// where the test harness runs a real `pico-guest-agent` in Unix listen
/// mode (`PICO_GUEST_AGENT_SOCKET`). The feature is
/// never enabled in release packaging. As an additional safety, the mock
/// path requires `PICO_SANDBOXD_ALLOW_MOCK=1` so a release artifact built
/// with the feature cannot be switched to mock mode by a single env var.
///
fn build_registry() -> AdapterRegistry {
    #[cfg(feature = "mock-backend")]
    if let Ok(path) = std::env::var("PICO_SANDBOXD_MOCK_GUEST_SOCKET")
        && !path.trim().is_empty()
        && std::env::var("PICO_SANDBOXD_ALLOW_MOCK").as_deref() == Ok("1")
    {
        return mock_registry(&path);
    }
    AdapterRegistry::default()
}

#[cfg(feature = "mock-backend")]
fn mock_registry(socket_path: &str) -> AdapterRegistry {
    use std::io::Write;
    use std::sync::Arc;
    use std::time::Duration;

    use pico_core::{BackendOperation, RuntimeType};
    use pico_runtime::mock::{MockBackend, MockBackendConfig, MockFailure};

    let guest_path = socket_path.to_string();
    // Each backend instantiation appends one line so binary-level tests can
    // prove a daemon restart never silently re-creates a runtime.
    let count_file = std::env::var("PICO_SANDBOXD_MOCK_BACKEND_COUNT_FILE").ok();
    let destroy_delay = std::env::var("PICO_SANDBOXD_MOCK_DESTROY_DELAY_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(|ms| MockFailure::Delay {
            operation: BackendOperation::Destroy,
            duration: Duration::from_millis(ms),
        });

    let mut registry = AdapterRegistry::new();
    let closure_path = guest_path.clone();
    registry.register(RuntimeType::Firecracker, move || {
        if let Some(path) = count_file.as_deref()
            && let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
        {
            let _ = writeln!(file, "backend-created");
        }
        Arc::new(MockBackend::new(MockBackendConfig {
            guest_transport_path: closure_path.clone(),
            failure: destroy_delay.clone(),
            ..MockBackendConfig::default()
        })) as Arc<dyn pico_core::RuntimeBackend>
    });
    info!(
        guest_socket = %guest_path,
        "mock-backend feature active: Firecracker slot serves MockBackend"
    );
    registry
}

#[tokio::main]
async fn main() -> Result<()> {
    let config =
        SandboxdConfig::from_file_or_env().context("failed to load sandboxd configuration")?;

    let telemetry_config = pico_telemetry::TelemetryConfig {
        settings: &pico_telemetry::TelemetrySettings {
            log: pico_telemetry::LogSettings {
                format: match config.log_format {
                    LogFormat::Pretty => pico_telemetry::LogFormat::Pretty,
                    LogFormat::Json => pico_telemetry::LogFormat::Json,
                },
                filter: "info,pico_sandboxd=debug".to_string(),
                ..Default::default()
            },
            metrics: pico_telemetry::MetricsSettings {
                service_name: "pico-sandboxd".to_string(),
                ..Default::default()
            },
            ..Default::default()
        },
    };

    let driver = pico_telemetry::init(telemetry_config)
        .map_err(|err| anyhow::anyhow!("failed to initialize telemetry: {err}"))?;
    tokio::spawn(driver);

    init_seccomp();

    info!(
        socket = %config.socket_path.display(),
        ledger = %config.ledger_path.display(),
        "sandboxd starting"
    );

    let registry = build_registry();
    server::run(config, registry, shutdown_signal()).await?;
    info!("sandboxd shutdown complete");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    info!("shutdown signal received");
}

//! Host-Agent standalone service binary.
//!
//! Starts the host-agent with an HTTP RPC surface for prepare, boot, exec,
//! suspend, resume, fork, destroy, stats, drain, and health. Supports
//! graceful shutdown under systemd.

use std::backtrace::Backtrace;
use std::panic::PanicHookInfo;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{Json, Router, extract::State, routing::get, routing::post};
use pico_host_agent::{
    HostAgent, HostControl, auth::BearerAuth, boot::BootCommand, config::HostAgentConfig,
};
use tokio::signal;
use tower_http::trace::{DefaultOnRequest, DefaultOnResponse, TraceLayer};
use tracing::{Level, Span, error, info, info_span};

use pico_core::{ExecRequest, SandboxService, SandboxSpec};

/// The RPC surface spans both seams: sandbox operations go through the core
/// [`SandboxService`], host-only operations through [`HostControl`]. Both are
/// backed by the same `HostAgent` in-process.
#[derive(Clone)]
struct AppState {
    facade: Arc<dyn SandboxService>,
    control: Arc<dyn HostControl>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let config =
        HostAgentConfig::from_file_or_env().context("failed to load host-agent configuration")?;

    let telemetry_config = pico_telemetry::TelemetryConfig {
        settings: &pico_telemetry::TelemetrySettings {
            log: pico_telemetry::LogSettings {
                format: match config.log_format {
                    pico_host_agent::config::LogFormat::Pretty => pico_telemetry::LogFormat::Pretty,
                    pico_host_agent::config::LogFormat::Json => pico_telemetry::LogFormat::Json,
                },
                filter: "info,pico_host_agent=debug,tower_http=debug".to_string(),
                ..Default::default()
            },
            metrics: pico_telemetry::MetricsSettings {
                service_name: "pico-host-agent".to_string(),
                otlp_endpoint: otlp_endpoint_from_env(),
                export_interval_secs: 60,
                resource_attributes: vec![
                    ("host_id".to_string(), config.identity.host_id.clone()),
                    ("cell_id".to_string(), config.identity.cell_id.clone()),
                    ("region".to_string(), config.identity.region.clone()),
                ],
            },
            tracing: pico_telemetry::TracingSettings {
                otlp_endpoint: otlp_endpoint_from_env(),
                sample_rate: 1.0,
            },
        },
    };

    let driver = pico_telemetry::init(telemetry_config)
        .map_err(|e| anyhow::anyhow!("failed to initialize telemetry: {e}"))?;

    tokio::spawn(driver);
    install_panic_hook();

    init_seccomp();

    let host_agent = HostAgent::from_config(&config)
        .await
        .context("failed to initialize host agent")?;
    host_agent.spawn_memory_pressure_poller();
    host_agent.spawn_observability_poller();
    host_agent.spawn_snapshot_optimizer_poller();
    let agent = Arc::new(host_agent);
    let state = AppState {
        facade: Arc::<HostAgent>::clone(&agent),
        control: agent,
    };

    let bind_addr = config.bind_addr;
    info!(
        host_id = %config.identity.host_id,
        cell_id = %config.identity.cell_id,
        region = %config.identity.region,
        bind_addr = %bind_addr,
        "host-agent starting"
    );

    let app = build_router(state.clone(), (*config.auth_token).clone());

    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .context("failed to bind TCP listener")?;

    info!(addr = %bind_addr, "host-agent RPC listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal(state, config.drain_timeout_secs))
        .await
        .context("server error")?;

    info!("host-agent shutdown complete");
    Ok(())
}

fn build_router(state: AppState, token: String) -> Router {
    let public = Router::new()
        .route("/rpc/v1/health", get(health_handler))
        .with_state(state.clone());

    let protected = Router::new()
        .route("/rpc/v1/inventory", get(inventory_handler))
        .route("/rpc/v1/stats", get(stats_handler))
        .route("/rpc/v1/prepare", post(prepare_handler))
        .route("/rpc/v1/boot", post(boot_handler))
        .route("/rpc/v1/exec", post(exec_handler))
        .route("/rpc/v1/suspend", post(suspend_handler))
        .route("/rpc/v1/resume", post(resume_handler))
        .route("/rpc/v1/fork", post(fork_handler))
        .route("/rpc/v1/destroy", post(destroy_handler))
        .route("/rpc/v1/drain", post(drain_handler))
        .with_state(state)
        .layer(BearerAuth::new(token));

    let trace_layer = TraceLayer::new_for_http()
        .make_span_with(make_request_span as fn(&axum::extract::Request) -> Span)
        .on_request(DefaultOnRequest::new().level(Level::INFO))
        .on_response(DefaultOnResponse::new().level(Level::INFO));

    Router::new()
        .merge(public)
        .merge(protected)
        .layer(trace_layer)
}

/// Creates a per-request tracing span, extracting any incoming W3C
/// `traceparent` / `tracestate` headers as the parent context.
fn make_request_span(request: &axum::extract::Request) -> Span {
    let traceparent = request
        .headers()
        .get("traceparent")
        .and_then(|v| v.to_str().ok());
    let tracestate = request
        .headers()
        .get("tracestate")
        .and_then(|v| v.to_str().ok());

    let span = info_span!(
        "host_agent_rpc",
        method = %request.method(),
        uri = %request.uri(),
    );

    pico_telemetry::trace_context::set_parent_from_trace_headers(&span, traceparent, tracestate);

    span
}

/// Readiness probe: reports `degraded` when sandboxd is unreachable or after
/// restart carries review findings. This is intentional for admission - the
/// cell controller should treat `degraded` as still serviceable but not fully
/// ready. Do not use this endpoint for kube-style liveness; process liveness
/// is simply whether the host-agent process is running.
async fn health_handler(
    State(state): State<AppState>,
) -> Json<pico_host_agent::health::HostHealth> {
    Json(state.control.health().await)
}

async fn inventory_handler(
    State(state): State<AppState>,
) -> Json<pico_host_agent::identity::HostInventory> {
    Json(state.control.inventory().await)
}

async fn stats_handler(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(state.control.stats().await)
}

#[derive(serde::Deserialize)]
struct PrepareRequest {
    spec: SandboxSpec,
}

async fn prepare_handler(
    State(state): State<AppState>,
    Json(req): Json<PrepareRequest>,
) -> Result<Json<pico_core::SandboxInfo>, ApiError> {
    state
        .control
        .prepare(req.spec)
        .await
        .map(Json)
        .map_err(ApiError::Internal)
}

async fn boot_handler(
    State(state): State<AppState>,
    Json(command): Json<BootCommand>,
) -> Result<Json<pico_host_agent::boot::BootReport>, ApiError> {
    state
        .control
        .boot_with_context(command)
        .await
        .map(Json)
        .map_err(ApiError::Internal)
}

#[derive(serde::Deserialize)]
struct ExecRpcRequest {
    sandbox_id: String,
    exec: ExecRequest,
}

async fn exec_handler(
    State(state): State<AppState>,
    Json(req): Json<ExecRpcRequest>,
) -> Result<Json<pico_core::ExecResponse>, ApiError> {
    state
        .facade
        .exec(&req.sandbox_id, req.exec)
        .await
        .map(Json)
        .map_err(ApiError::Internal)
}

#[derive(serde::Deserialize)]
struct SandboxIdRequest {
    sandbox_id: String,
}

async fn suspend_handler(
    State(state): State<AppState>,
    Json(req): Json<SandboxIdRequest>,
) -> Result<Json<()>, ApiError> {
    state
        .facade
        .suspend(&req.sandbox_id)
        .await
        .map(Json)
        .map_err(ApiError::Internal)
}

async fn resume_handler(
    State(state): State<AppState>,
    Json(req): Json<SandboxIdRequest>,
) -> Result<Json<()>, ApiError> {
    state
        .facade
        .resume(&req.sandbox_id)
        .await
        .map(Json)
        .map_err(ApiError::Internal)
}

#[derive(serde::Deserialize)]
struct ForkRequest {
    sandbox_id: String,
    new_spec: SandboxSpec,
}

async fn fork_handler(
    State(state): State<AppState>,
    Json(req): Json<ForkRequest>,
) -> Result<Json<pico_core::SandboxInfo>, ApiError> {
    state
        .control
        .fork(&req.sandbox_id, req.new_spec)
        .await
        .map(Json)
        .map_err(ApiError::Internal)
}

async fn destroy_handler(
    State(state): State<AppState>,
    Json(req): Json<SandboxIdRequest>,
) -> Result<Json<()>, ApiError> {
    state
        .facade
        .destroy(&req.sandbox_id)
        .await
        .map(Json)
        .map_err(ApiError::Internal)
}

async fn drain_handler(State(state): State<AppState>) -> Result<Json<()>, ApiError> {
    state
        .control
        .drain()
        .await
        .map(Json)
        .map_err(ApiError::Internal)
}

#[derive(Debug)]
pub enum ApiError {
    Internal(pico_core::SandboxError),
}

impl axum::response::IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            ApiError::Internal(err) => {
                let status = match err {
                    pico_core::SandboxError::SandboxNotFound(_) => {
                        axum::http::StatusCode::NOT_FOUND
                    }
                    pico_core::SandboxError::BadRequest(_) => axum::http::StatusCode::BAD_REQUEST,
                    pico_core::SandboxError::Conflict(_) => axum::http::StatusCode::CONFLICT,
                    pico_core::SandboxError::OperationStale(_) => axum::http::StatusCode::CONFLICT,
                    pico_core::SandboxError::Unprocessable(_)
                    | pico_core::SandboxError::QuotaExceeded { .. }
                    | pico_core::SandboxError::ResourceExhausted { .. }
                    | pico_core::SandboxError::InvalidStateTransition(_) => {
                        axum::http::StatusCode::UNPROCESSABLE_ENTITY
                    }
                    pico_core::SandboxError::NotImplemented(_) => {
                        axum::http::StatusCode::NOT_IMPLEMENTED
                    }
                    pico_core::SandboxError::Unauthorized => axum::http::StatusCode::UNAUTHORIZED,
                    pico_core::SandboxError::NotReady(_) => {
                        axum::http::StatusCode::SERVICE_UNAVAILABLE
                    }
                    _ => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                };
                (status, err.to_string())
            }
        };
        (status, message).into_response()
    }
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

        error!("HOST_AGENT_BOOT: panic at {location}: {payload}");
        error!(
            "HOST_AGENT_BOOT: backtrace:\n{}",
            Backtrace::force_capture()
        );

        default_hook(panic_info);
    }));
}

fn init_seccomp() {
    use pico_seccomp::CapabilitySet;
    use pico_seccomp::ComponentProfile;
    use tracing::info;

    info!("initializing seccomp and capability minimization for host-agent");

    let _ = pico_seccomp::init_profile_for_component_with_strictness(
        ComponentProfile::HostAgent,
        &CapabilitySet::host_agent(),
        true,
        false,
    );

    // Network agent still co-resides; runtime adapters no longer link into
    // host-agent after the sandboxd cutover.
    pico_network_agent::init_seccomp();
}

/// OTLP gRPC collector endpoint. Empty means no export (local dev default).
fn otlp_endpoint_from_env() -> String {
    std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .map(|v| v.trim().to_string())
        .unwrap_or_default()
}

async fn shutdown_signal(agent: AppState, drain_timeout_secs: u64) {
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
    if let Err(err) = agent.control.drain().await {
        error!(error = %err, "failed to mark host-agent draining during shutdown");
    }
    if drain_timeout_secs > 0 {
        tokio::time::sleep(std::time::Duration::from_secs(drain_timeout_secs)).await;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use serde_json::Value;
    use tower::ServiceExt;

    use super::*;
    use pico_core::{
        FileInfo, FileReadResponse, FileWriteRequest, Result, SandboxInfo, SshInfo, TaskEvent,
        TaskInfo, TaskRequest,
    };
    use tokio::sync::broadcast;

    struct NoopAgent;

    #[async_trait]
    impl SandboxService for NoopAgent {
        async fn create(&self, _: SandboxSpec) -> Result<SandboxInfo> {
            unimplemented!()
        }

        async fn list(
            &self,
            _: usize,
            _: Option<String>,
        ) -> Result<(Vec<SandboxInfo>, Option<String>)> {
            unimplemented!()
        }

        async fn get(&self, _: &str) -> Result<SandboxInfo> {
            unimplemented!()
        }

        async fn destroy(&self, _: &str) -> Result<()> {
            unimplemented!()
        }

        async fn purge(&self, _: &str) -> Result<()> {
            unimplemented!()
        }

        async fn stop(&self, _: &str) -> Result<()> {
            unimplemented!()
        }

        async fn keepalive(&self, _: &str) -> Result<()> {
            unimplemented!()
        }

        async fn exec(&self, _: &str, _: ExecRequest) -> Result<pico_core::ExecResponse> {
            unimplemented!()
        }

        async fn file_read(&self, _: &str, _: &str) -> Result<FileReadResponse> {
            unimplemented!()
        }

        async fn file_write(&self, _: &str, _: FileWriteRequest) -> Result<FileInfo> {
            unimplemented!()
        }

        async fn file_list(&self, _: &str, _: &str, _: bool) -> Result<Vec<FileInfo>> {
            unimplemented!()
        }

        async fn task_start(&self, _: &str, _: TaskRequest) -> Result<TaskInfo> {
            unimplemented!()
        }

        async fn task_get(&self, _: &str, _: &str) -> Result<TaskInfo> {
            unimplemented!()
        }

        async fn task_cancel(&self, _: &str, _: &str) -> Result<()> {
            unimplemented!()
        }

        fn task_subscribe(&self, _: &str, _: &str) -> Result<broadcast::Receiver<TaskEvent>> {
            unimplemented!()
        }

        async fn ssh_info(&self, _: &str) -> Result<SshInfo> {
            unimplemented!()
        }
    }

    #[async_trait]
    impl HostControl for NoopAgent {
        async fn health(&self) -> pico_host_agent::health::HostHealth {
            pico_host_agent::health::HostHealth::ready(0, vec![])
        }

        async fn inventory(&self) -> pico_host_agent::identity::HostInventory {
            let boot = pico_host_agent::identity::HostCapacity {
                cpu_count: 1,
                memory_mb_total: 1,
                memory_mb_available: 1,
                disk_mb_total: 1,
                disk_mb_available: 1,
            };
            pico_host_agent::identity::HostInventory {
                identity: pico_host_agent::identity::HostIdentity::new(
                    "mock-host".into(),
                    "mock-cell".into(),
                    "mock-region".into(),
                ),
                capacity: boot.clone(),
                supported_backends: vec![],
                agent_version: "test".into(),
                scheduler_capacity: Some(pico_host_agent::scheduler_capacity::scheduler_capacity(
                    &boot,
                    pico_host_agent::scheduler_capacity::AllocatedResources::default(),
                )),
                pressure: Some(pico_host_agent::scheduler_capacity::scheduler_pressure(
                    0, 0,
                )),
                current_sandboxes: 0,
            }
        }

        async fn stats(&self) -> serde_json::Value {
            serde_json::json!({"sandbox_count": 0})
        }
    }

    fn app() -> Router {
        let agent = Arc::new(NoopAgent);
        let state = AppState {
            facade: Arc::<NoopAgent>::clone(&agent),
            control: agent,
        };
        build_router(state, "secret".into())
    }

    #[tokio::test]
    async fn health_route_is_public() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/rpc/v1/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn protected_routes_require_auth() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/rpc/v1/stats")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["error"], "Unauthorized");
    }

    #[tokio::test]
    async fn protected_routes_accept_valid_bearer_token() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/rpc/v1/stats")
                    .header("authorization", "Bearer secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}

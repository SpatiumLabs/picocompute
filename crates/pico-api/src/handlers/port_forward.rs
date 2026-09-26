//! Port-forward endpoint handlers.
//!
//! Exposes controlled ingress to sandbox guest services. Every create
//! requires a valid access lease; the host agent validates the lease and
//! binds a platform-managed listener.

use axum::Json;
use axum::extract::{Path, State};
use pico_core::{PortForwardEndpoint, PortForwardRequest, PortForwardResponse};

use crate::error::AppError;
use crate::state::AppState;

pub(crate) async fn expose(
    State(agent): State<AppState>,
    Path(sandbox_id): Path<String>,
    Json(req): Json<PortForwardRequest>,
) -> Result<Json<PortForwardResponse>, AppError> {
    let endpoint = agent.expose_port(&sandbox_id, req).await?;
    Ok(Json(PortForwardResponse { endpoint }))
}

pub(crate) async fn list(
    State(agent): State<AppState>,
    Path(sandbox_id): Path<String>,
) -> Result<Json<Vec<PortForwardEndpoint>>, AppError> {
    agent
        .list_ports(&sandbox_id)
        .await
        .map(Json)
        .map_err(AppError::from)
}

pub(crate) async fn revoke(
    State(agent): State<AppState>,
    Path((sandbox_id, endpoint_id)): Path<(String, String)>,
) -> Result<Json<PortForwardResponse>, AppError> {
    agent
        .revoke_port(&sandbox_id, &endpoint_id)
        .await
        .map(Json)
        .map_err(AppError::from)
}

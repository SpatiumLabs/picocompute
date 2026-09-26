//! Access-lease issuance handler.

use axum::Json;
use axum::extract::{Path, State};
use pico_core::{LeaseAction, LeaseScope};
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub(crate) struct IssueLeaseBody {
    action: String,
    #[serde(default)]
    scope: Option<LeaseScope>,
}

#[derive(Debug, Serialize)]
pub(crate) struct IssueLeaseResponse {
    lease: String,
    lease_id: String,
    expires_at: String,
    action: String,
}

pub(crate) async fn issue(
    State(agent): State<AppState>,
    Path(sandbox_id): Path<String>,
    Json(body): Json<IssueLeaseBody>,
) -> Result<Json<IssueLeaseResponse>, AppError> {
    let action = LeaseAction::from_name(&body.action)
        .ok_or_else(|| AppError::BadRequest(format!("unknown lease action: {}", body.action)))?;
    let scope = body.scope.unwrap_or_else(LeaseScope::unbounded);
    if action.requires_explicit_scope() && !scope.has_bounds_for(action) {
        return Err(AppError::BadRequest(format!(
            "action {} requires explicit scope bounds",
            action.as_str()
        )));
    }
    let issued = agent.issue_access_lease(&sandbox_id, action, scope).await?;
    let blob = pico_core::encode_lease_blob(&issued)
        .map_err(|e| AppError::BadRequest(format!("failed to encode lease: {e}")))?;
    Ok(Json(IssueLeaseResponse {
        lease: blob,
        lease_id: issued.lease_id.to_string(),
        expires_at: issued.expires_at,
        action: issued.action.as_str().to_string(),
    }))
}

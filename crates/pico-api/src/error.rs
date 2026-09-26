//! HTTP-facing error mapping from domain failures into API responses.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use pico_core::SandboxError;
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error(transparent)]
    Sandbox(#[from] SandboxError),
    #[error("malformed request: {0}")]
    BadRequest(String),
    #[error("missing or invalid Authorization header")]
    Unauthorized,
}

impl AppError {
    fn parts(&self) -> (StatusCode, &'static str) {
        match self {
            AppError::Sandbox(s) => match s {
                SandboxError::SandboxNotFound(_)
                | SandboxError::TaskNotFound(_)
                | SandboxError::WorkspaceNotFound(_) => (StatusCode::NOT_FOUND, "NotFound"),
                SandboxError::BadRequest(_) | SandboxError::PathEscape(_) => {
                    (StatusCode::BAD_REQUEST, "BadRequest")
                }
                SandboxError::Conflict(_)
                | SandboxError::InvalidStateTransition(_)
                | SandboxError::VersionConflict(_)
                | SandboxError::OperationStale(_) => (StatusCode::CONFLICT, "Conflict"),
                SandboxError::PortInUse(_) => (StatusCode::CONFLICT, "PortInUse"),
                SandboxError::Unprocessable(_) => {
                    (StatusCode::UNPROCESSABLE_ENTITY, "Unprocessable")
                }
                SandboxError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized"),
                SandboxError::NotImplemented(_) => (StatusCode::NOT_IMPLEMENTED, "NotImplemented"),
                SandboxError::NotReady(_) => {
                    (StatusCode::SERVICE_UNAVAILABLE, "ServiceUnavailable")
                }
                SandboxError::Io(_)
                | SandboxError::Other(_)
                | SandboxError::CgroupSetupFailed { .. }
                | SandboxError::CgroupCleanupFailed { .. } => {
                    (StatusCode::INTERNAL_SERVER_ERROR, "Internal")
                }
                SandboxError::QuotaExceeded { .. } => {
                    (StatusCode::TOO_MANY_REQUESTS, "QuotaExceeded")
                }
                SandboxError::ResourceExhausted { .. } => {
                    (StatusCode::TOO_MANY_REQUESTS, "ResourceExhausted")
                }
                SandboxError::PolicyDenied { .. } => (StatusCode::FORBIDDEN, "PolicyDenied"),
                SandboxError::BackendSelectionRejected { .. } => {
                    (StatusCode::UNPROCESSABLE_ENTITY, "BackendSelectionRejected")
                }
                SandboxError::PlacementThrottled { .. } => {
                    (StatusCode::UNPROCESSABLE_ENTITY, "PlacementThrottled")
                }
            },
            AppError::BadRequest(_) => (StatusCode::BAD_REQUEST, "BadRequest"),
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized"),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code) = self.parts();
        let message = self.to_string();
        if status.is_server_error() {
            tracing::error!(error = %message, "server error");
        }
        // Fail closed with a retry hint: throttled placement keeps the 422
        // contract but signals `Retry-After` so clients back off instead of
        // hammering admission or expecting silent backend fallback.
        let retry_after_secs = match &self {
            AppError::Sandbox(SandboxError::PlacementThrottled {
                retry_after_secs, ..
            }) => Some(*retry_after_secs),
            _ => None,
        };
        let body = Json(json!({"error": code, "message": message, "status": status.as_u16()}));
        if let Some(secs) = retry_after_secs {
            let mut headers = axum::http::HeaderMap::new();
            headers.insert(
                axum::http::header::RETRY_AFTER,
                axum::http::HeaderValue::from_str(&secs.to_string())
                    .unwrap_or(axum::http::HeaderValue::from_static("30")),
            );
            (status, headers, body).into_response()
        } else {
            (status, body).into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_found_maps_to_404() {
        let e: AppError = SandboxError::SandboxNotFound("x".into()).into();
        assert_eq!(e.parts().0, StatusCode::NOT_FOUND);
    }

    #[test]
    fn bad_request_maps_to_400() {
        let e: AppError = SandboxError::BadRequest("nope".into()).into();
        assert_eq!(e.parts().0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn port_in_use_maps_to_409_with_specific_code() {
        let e: AppError = SandboxError::PortInUse(3000).into();
        assert_eq!(e.parts(), (StatusCode::CONFLICT, "PortInUse"));
    }

    #[test]
    fn not_implemented_maps_to_501() {
        let e: AppError = SandboxError::NotImplemented("file_read").into();
        assert_eq!(e.parts().0, StatusCode::NOT_IMPLEMENTED);
    }

    #[test]
    fn io_maps_to_500() {
        let io = std::io::Error::other("boom");
        let e: AppError = SandboxError::Io(io).into();
        assert_eq!(e.parts().0, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn quota_exceeded_maps_to_429() {
        let e: AppError = SandboxError::QuotaExceeded {
            resource: "vcpus".into(),
            limit: 32,
            current: 32,
        }
        .into();
        assert_eq!(e.parts().0, StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn resource_exhausted_maps_to_429_without_quota_numbers() {
        let e: AppError = SandboxError::ResourceExhausted {
            detail: "sandboxd: file out.bin exceeds max_bytes 1024".into(),
        }
        .into();
        assert_eq!(
            e.parts(),
            (StatusCode::TOO_MANY_REQUESTS, "ResourceExhausted")
        );
    }

    #[test]
    fn policy_denied_maps_to_403() {
        let e: AppError = SandboxError::PolicyDenied {
            reason: "untrusted".into(),
        }
        .into();
        assert_eq!(e.parts().0, StatusCode::FORBIDDEN);
    }

    #[test]
    fn placement_throttled_maps_to_422_with_retry_after() {
        use axum::http::header::RETRY_AFTER;
        let e: AppError = SandboxError::PlacementThrottled {
            reason: "pressure saturated".into(),
            retry_after_secs: 30,
        }
        .into();
        assert_eq!(
            e.parts(),
            (StatusCode::UNPROCESSABLE_ENTITY, "PlacementThrottled")
        );
        let response = e.into_response();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let retry_after = response
            .headers()
            .get(RETRY_AFTER)
            .expect("throttled placement must carry Retry-After");
        assert_eq!(retry_after, "30");
    }
}

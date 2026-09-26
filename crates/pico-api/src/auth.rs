//! Bearer token middleware for protecting non-health API routes.

use axum::Json;
use axum::body::Body;
use axum::http::{Request, Response};
use axum::response::IntoResponse;
use serde_json::json;
use std::pin::Pin;
use std::task::{Context, Poll};
use subtle::ConstantTimeEq;
use tower::{Layer, Service};

#[derive(Clone)]
pub(crate) struct BearerAuth {
    token: String,
}

impl BearerAuth {
    pub(crate) fn new(token: String) -> Self {
        Self { token }
    }
}

impl<S> Layer<S> for BearerAuth {
    type Service = BearerAuthMiddleware<S>;
    fn layer(&self, inner: S) -> Self::Service {
        BearerAuthMiddleware {
            inner,
            token: self.token.clone(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct BearerAuthMiddleware<S> {
    inner: S,
    token: String,
}

impl<S> Service<Request<Body>> for BearerAuthMiddleware<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let token = self.token.clone();
        let mut inner = self.inner.clone();
        Box::pin(async move {
            let presented = req
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "));
            let authorized = presented
                .map(|t| bool::from(t.as_bytes().ct_eq(token.as_bytes())))
                .unwrap_or(false);
            if !authorized {
                let body = (
                    axum::http::StatusCode::UNAUTHORIZED,
                    Json(json!({
                        "error": "Unauthorized",
                        "message": "missing or invalid Authorization header",
                        "status": 401,
                    })),
                )
                    .into_response();
                return Ok(body);
            }
            inner.call(req).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use tower::ServiceExt;

    async fn ok() -> &'static str {
        "ok"
    }

    fn app(token: &str) -> Router {
        Router::new()
            .route("/", get(ok))
            .layer(BearerAuth::new(token.into()))
    }

    #[tokio::test]
    async fn rejects_missing_header() {
        let resp = app("secret")
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn rejects_wrong_token() {
        let resp = app("secret")
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("authorization", "Bearer wrong")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn accepts_correct_token() {
        let resp = app("secret")
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("authorization", "Bearer secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}

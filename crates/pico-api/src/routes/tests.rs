use std::sync::Arc;

use async_trait::async_trait;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use pico_core::{
    ExecRequest, ExecResponse, FileInfo, FileReadResponse, FileWriteRequest, Result, SandboxError,
    SandboxInfo, SandboxSpec, SshInfo, TaskEvent, TaskInfo, TaskRequest,
};
use serde_json::Value;
use tokio::sync::broadcast;
use tower::ServiceExt;

use super::*;

struct RouterMock;

#[async_trait]
impl pico_core::SandboxService for RouterMock {
    async fn create(&self, _: SandboxSpec) -> Result<SandboxInfo> {
        Err(SandboxError::Other("backend unavailable".into()))
    }

    async fn list(
        &self,
        _: usize,
        _: Option<String>,
    ) -> Result<(Vec<SandboxInfo>, Option<String>)> {
        Ok((Vec::new(), None))
    }

    async fn get(&self, id: &str) -> Result<SandboxInfo> {
        Err(SandboxError::SandboxNotFound(id.into()))
    }

    async fn destroy(&self, _: &str) -> Result<()> {
        Ok(())
    }

    async fn purge(&self, _: &str) -> Result<()> {
        Ok(())
    }

    async fn stop(&self, _: &str) -> Result<()> {
        Ok(())
    }

    async fn keepalive(&self, _: &str) -> Result<()> {
        Ok(())
    }

    async fn exec(&self, _: &str, _: ExecRequest) -> Result<ExecResponse> {
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

fn app() -> Router {
    build_router(Arc::new(RouterMock), "secret".into())
}

#[tokio::test]
async fn health_routes_do_not_require_auth() {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/v1/livez")
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
                .uri("/v1/sandboxes")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["error"], "Unauthorized");
    assert_eq!(value["status"], 401);
}

#[tokio::test]
async fn request_id_is_generated_for_responses() {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/v1/livez")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(response.headers().get("x-request-id").is_some());
}

#[tokio::test]
async fn incoming_request_id_is_preserved() {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/v1/livez")
                .header("x-request-id", "request-123")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.headers().get("x-request-id").unwrap(),
        "request-123"
    );
}

#[tokio::test]
async fn port_forward_routes_require_auth() {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/v1/sandboxes/sbx/ports")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn port_forward_expose_returns_not_implemented_by_default() {
    let body = serde_json::json!({
        "tenant_id": "tnt_test",
        "lease_id": "lse_test",
        "guest_port": 8080,
    })
    .to_string();

    let response = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/sandboxes/sbx/ports")
                .header("authorization", "Bearer secret")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
}

#[tokio::test]
async fn suspend_and_resume_fail_closed_when_backend_is_unsupported() {
    for uri in ["/v1/sandboxes/sbx/suspend", "/v1/sandboxes/sbx/resume"] {
        let response = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("authorization", "Bearer secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }
}

#[tokio::test]
async fn job_routes_require_auth() {
    for uri in ["/v1/jobs/job_x/pause", "/v1/jobs/job_x/resume"] {
        let response = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn job_routes_fail_closed_when_backend_is_unsupported() {
    for uri in ["/v1/jobs/job_x/pause", "/v1/jobs/job_x/resume"] {
        let response = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("authorization", "Bearer secret")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"job_id":"job_x","sandbox_ids":["sbx_abc123"],"fencing_token":{"epoch":1,"sequence":1},"policy_epoch":1,"deadline_secs":60,"reason":"test"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }
}

#[tokio::test]
async fn job_route_rejects_path_body_id_mismatch() {
    let response = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/jobs/job_path/pause")
                .header("authorization", "Bearer secret")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"job_id":"job_body","sandbox_ids":["sbx_abc123"],"fencing_token":{"epoch":1,"sequence":1},"policy_epoch":1,"deadline_secs":60,"reason":"test"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn app_errors_are_returned_as_json() {
    let response = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/sandboxes")
                .header("authorization", "Bearer secret")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["error"], "Internal");
    assert_eq!(value["status"], 500);
}

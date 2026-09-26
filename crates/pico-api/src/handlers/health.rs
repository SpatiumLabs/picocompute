//! Liveness and readiness handlers for the platform API.

use axum::extract::State;
use axum::http::StatusCode;

use crate::state::AppState;

pub(crate) async fn livez() -> &'static str {
    "OK"
}

/// Phase 1: always 200. Chunk 3 may tighten this to ping the runtime backend.
pub(crate) async fn readyz(State(_agent): State<AppState>) -> (StatusCode, &'static str) {
    (StatusCode::OK, "OK")
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use pico_core::{
        ExecRequest, ExecResponse, FileInfo, FileReadResponse, FileWriteRequest, Result,
        SandboxInfo, SandboxSpec, SshInfo, TaskEvent, TaskInfo, TaskRequest,
    };
    use std::sync::Arc;
    use tokio::sync::broadcast;

    struct NoopAgent;
    #[async_trait]
    impl pico_core::SandboxService for NoopAgent {
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

    #[tokio::test]
    async fn livez_returns_ok() {
        assert_eq!(livez().await, "OK");
    }

    #[tokio::test]
    async fn readyz_returns_ok() {
        let s: AppState = Arc::new(NoopAgent);
        let (status, body) = readyz(State(s)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "OK");
    }
}

//! Command execution handlers for sandbox guests.

use axum::Json;
use axum::extract::{Path, State};
use pico_core::{ExecRequest, ExecResponse, SandboxFacade};

use crate::error::AppError;
use crate::state::{AppState, lifecycle};

pub(crate) async fn exec(
    State(agent): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<ExecRequest>,
) -> Result<Json<ExecResponse>, AppError> {
    Ok(Json(lifecycle(&agent).exec(&id, req).await?))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use pico_core::{
        FileInfo, FileReadResponse, FileWriteRequest, Result, SandboxInfo, SandboxSpec, SshInfo,
        TaskEvent, TaskInfo, TaskRequest,
    };
    use tokio::sync::broadcast;

    use super::*;

    struct ExecMock;

    #[async_trait]
    impl pico_core::SandboxService for ExecMock {
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
            Ok(())
        }

        async fn keepalive(&self, _: &str) -> Result<()> {
            Ok(())
        }

        async fn exec(&self, _: &str, _: ExecRequest) -> Result<ExecResponse> {
            Ok(ExecResponse {
                exit_code: 0,
                stdout: "ok".into(),
                stderr: String::new(),
                duration_ms: 5,
            })
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
    async fn exec_returns_response() {
        let s: AppState = Arc::new(ExecMock);
        let resp = exec(
            State(s),
            Path("sbx_x".into()),
            Json(ExecRequest {
                command: "echo".into(),
                args: vec!["ok".into()],
                env: None,
                working_dir: None,
                timeout_secs: None,
            }),
        )
        .await
        .unwrap();
        assert_eq!(resp.0.stdout, "ok");
    }
}

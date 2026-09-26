//! SSH connection info handlers.

use axum::Json;
use axum::extract::{Path, State};
use pico_core::SshInfo;

use crate::error::AppError;
use crate::state::AppState;

pub(crate) async fn ssh_info(
    State(agent): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<SshInfo>, AppError> {
    let info = agent.ssh_info(&id).await?;
    Ok(Json(info))
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use hashbrown::HashMap;
    use pico_core::{
        ExecRequest, ExecResponse, FileInfo, FileReadResponse, FileWriteRequest, Result,
        SandboxInfo, SandboxSpec, SshInfo, TaskEvent, TaskInfo, TaskRequest,
    };
    use std::sync::{Arc, Mutex};
    use tokio::sync::broadcast;

    struct MockAgent {
        items: Mutex<HashMap<String, SandboxInfo>>,
    }

    #[async_trait]
    impl pico_core::SandboxService for MockAgent {
        async fn create(&self, s: SandboxSpec) -> Result<SandboxInfo> {
            let id = s.id.clone().unwrap_or_else(|| pico_core::new_ulid("sbx"));
            let info = SandboxInfo {
                id: id.clone(),
                state: pico_core::SandboxState::Running,
                ports: s.ports.unwrap_or_default(),
                container_id: None,
                created_at: "2026-06-04T00:00:00Z".into(),
                last_activity_at: "2026-06-04T00:00:00Z".into(),
                ssh_port: Some(22),
                ssh_public_key: Some("ssh-ed25519 test-key".into()),
            };
            self.items.lock().unwrap().insert(id, info.clone());
            Ok(info)
        }
        async fn list(
            &self,
            _l: usize,
            _c: Option<String>,
        ) -> Result<(Vec<SandboxInfo>, Option<String>)> {
            unimplemented!()
        }
        async fn get(&self, _id: &str) -> Result<SandboxInfo> {
            unimplemented!()
        }
        async fn destroy(&self, _id: &str) -> Result<()> {
            unimplemented!()
        }
        async fn purge(&self, _id: &str) -> Result<()> {
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
        async fn ssh_info(&self, _id: &str) -> Result<SshInfo> {
            Ok(SshInfo {
                host: "localhost".into(),
                port: 22,
                username: "root".into(),
                private_key: Some("private-key".into()),
                public_key: "ssh-ed25519 test-key".into(),
            })
        }
    }

    fn state() -> AppState {
        Arc::new(MockAgent {
            items: Mutex::new(HashMap::new()),
        })
    }

    #[tokio::test]
    async fn ssh_info_returns_connection_info() {
        let s = state();
        let info = ssh_info(State(s), Path("sbx_test".into())).await.unwrap();
        assert_eq!(info.0.host, "localhost");
        assert_eq!(info.0.port, 22);
        assert_eq!(info.0.username, "root");
        assert!(info.0.private_key.is_some());
        assert_eq!(info.0.public_key, "ssh-ed25519 test-key");
    }
}

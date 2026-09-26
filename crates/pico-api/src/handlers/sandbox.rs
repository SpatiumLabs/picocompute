//! Sandbox lifecycle and listing handlers for the platform API.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use pico_core::{PageRequest, PageResponse, SandboxFacade, SandboxInfo, SandboxSpec};

use crate::error::AppError;
use crate::state::{AppState, lifecycle};

pub(crate) async fn create(
    State(agent): State<AppState>,
    Json(spec): Json<SandboxSpec>,
) -> Result<(StatusCode, Json<SandboxInfo>), AppError> {
    let info = lifecycle(&agent).create(spec).await?;
    Ok((StatusCode::CREATED, Json(info)))
}

pub(crate) async fn list(
    State(agent): State<AppState>,
    Query(page): Query<PageRequest>,
) -> Result<Json<PageResponse<SandboxInfo>>, AppError> {
    let (limit, cursor) = page.normalized()?;
    let (items, next_cursor) = lifecycle(&agent).list(limit, cursor).await?;
    Ok(Json(PageResponse { items, next_cursor }))
}

pub(crate) async fn get_one(
    State(agent): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<SandboxInfo>, AppError> {
    Ok(Json(lifecycle(&agent).get(&id).await?))
}

pub(crate) async fn destroy(
    State(agent): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    lifecycle(&agent).destroy(&id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn purge(
    State(agent): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    lifecycle(&agent).purge(&id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn stop(
    State(agent): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    lifecycle(&agent).stop(&id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn keepalive(
    State(agent): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    lifecycle(&agent).keepalive(&id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn suspend(
    State(agent): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    lifecycle(&agent).suspend(&id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn resume(
    State(agent): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    lifecycle(&agent).resume(&id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use axum::response::IntoResponse;
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
            l: usize,
            c: Option<String>,
        ) -> Result<(Vec<SandboxInfo>, Option<String>)> {
            let items = self.items.lock().unwrap();
            let mut ids: Vec<&String> = items.keys().collect();
            ids.sort();
            let start = match c {
                Some(s) => ids
                    .iter()
                    .position(|id| id.as_str() > s.as_str())
                    .unwrap_or(ids.len()),
                None => 0,
            };
            let end = (start + l).min(ids.len());
            let slice: Vec<SandboxInfo> = ids[start..end]
                .iter()
                .map(|id| items.get(*id).unwrap().clone())
                .collect();
            let next = if end < ids.len() {
                slice.last().map(|i| i.id.clone())
            } else {
                None
            };
            Ok((slice, next))
        }
        async fn get(&self, id: &str) -> Result<SandboxInfo> {
            self.items
                .lock()
                .unwrap()
                .get(id)
                .cloned()
                .ok_or(pico_core::SandboxError::SandboxNotFound(id.into()))
        }
        async fn destroy(&self, id: &str) -> Result<()> {
            self.items.lock().unwrap().remove(id);
            Ok(())
        }
        async fn purge(&self, id: &str) -> Result<()> {
            self.destroy(id).await
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

    fn spec(id: &str) -> SandboxSpec {
        SandboxSpec {
            runtime: None,
            id: Some(id.into()),
            ports: Some(vec![3000]),
            env: None,
            memory_mb: None,
            vcpus: None,
            idle_timeout_secs: None,
            ssh_public_key: None,
            ssh_key_type: None,
            image_id: None,
            image_digest: None,
            credential_request: None,
        }
    }

    #[tokio::test]
    async fn create_returns_201() {
        let s = state();
        let (status, body) = create(State(s), Json(spec("sbx_test"))).await.unwrap();
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(body.0.id, "sbx_test");
        assert_eq!(body.0.ports, vec![3000]);
    }

    #[tokio::test]
    async fn list_paginates() {
        let s = state();
        for i in 0..3 {
            let _ = create(
                State(Arc::clone(&s)),
                Json(SandboxSpec {
                    runtime: None,
                    id: Some(format!("sbx_{:02}", i)),
                    ports: None,
                    env: None,
                    memory_mb: None,
                    vcpus: None,
                    idle_timeout_secs: None,
                    ssh_public_key: None,
                    ssh_key_type: None,
                    image_id: None,
                    image_digest: None,
                    credential_request: None,
                }),
            )
            .await
            .unwrap();
        }
        let p1 = list(
            State(Arc::clone(&s)),
            Query(PageRequest {
                limit: Some(2),
                cursor: None,
            }),
        )
        .await
        .unwrap();
        assert_eq!(p1.0.items.len(), 2);
        assert!(p1.0.next_cursor.is_some());
        let p2 = list(
            State(Arc::clone(&s)),
            Query(PageRequest {
                limit: Some(2),
                cursor: p1.0.next_cursor.clone(),
            }),
        )
        .await
        .unwrap();
        assert_eq!(p2.0.items.len(), 1);
        assert!(p2.0.next_cursor.is_none());
    }

    #[tokio::test]
    async fn list_rejects_oversized_limit() {
        let s = state();
        let err = list(
            State(s),
            Query(PageRequest {
                limit: Some(10_000),
                cursor: None,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.into_response().status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_missing_returns_404() {
        let s = state();
        let err = get_one(State(s), Path("sbx_missing".into()))
            .await
            .unwrap_err();
        assert_eq!(err.into_response().status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn keepalive_returns_204() {
        let s = state();
        let _ = create(State(Arc::clone(&s)), Json(spec("sbx_ka")))
            .await
            .unwrap();
        assert_eq!(
            keepalive(State(s), Path("sbx_ka".into())).await.unwrap(),
            StatusCode::NO_CONTENT
        );
    }

    #[tokio::test]
    async fn destroy_returns_204_then_404_on_get() {
        let s = state();
        let _ = create(State(Arc::clone(&s)), Json(spec("sbx_d")))
            .await
            .unwrap();
        assert_eq!(
            destroy(State(Arc::clone(&s)), Path("sbx_d".into()))
                .await
                .unwrap(),
            StatusCode::NO_CONTENT
        );
        let err = get_one(State(s), Path("sbx_d".into())).await.unwrap_err();
        assert_eq!(err.into_response().status(), StatusCode::NOT_FOUND);
    }
}

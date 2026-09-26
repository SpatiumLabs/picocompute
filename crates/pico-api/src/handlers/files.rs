//! File read, write, and listing handlers for sandbox workspaces.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use pico_core::{FileInfo, FileWriteRequest, PageRequest, PageResponse};
use serde::Deserialize;

use crate::error::AppError;
use crate::state::AppState;

pub(crate) async fn get(
    State(agent): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<FileGetQuery>,
) -> Result<Response, AppError> {
    match (query.path, query.dir) {
        (Some(path), None) => {
            let response = agent.file_read(&id, &path).await?;
            Ok(Json(response).into_response())
        }
        (None, Some(dir)) => {
            let page = PageRequest {
                limit: query.limit,
                cursor: query.cursor,
            };
            let (limit, cursor) = page.normalized()?;
            let files = agent.file_list(&id, &dir, query.recursive).await?;
            let (items, next_cursor) = paginate(&files, limit, cursor.as_deref());
            Ok(Json(PageResponse { items, next_cursor }).into_response())
        }
        (Some(_), Some(_)) => Err(AppError::BadRequest(
            "provide exactly one of `path` or `dir`".into(),
        )),
        (None, None) => Err(AppError::BadRequest("provide `path` or `dir`".into())),
    }
}

pub(crate) async fn put(
    State(agent): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<FileWriteRequest>,
) -> Result<(StatusCode, Json<FileInfo>), AppError> {
    let info = agent.file_write(&id, req).await?;
    Ok((StatusCode::OK, Json(info)))
}

#[derive(Debug, Deserialize)]
pub(crate) struct FileGetQuery {
    pub path: Option<String>,
    pub dir: Option<String>,
    #[serde(default)]
    pub recursive: bool,
    pub limit: Option<usize>,
    pub cursor: Option<String>,
}

fn paginate(
    items: &[FileInfo],
    limit: usize,
    cursor: Option<&str>,
) -> (Vec<FileInfo>, Option<String>) {
    let start = match cursor {
        Some(cursor) => items
            .iter()
            .position(|item| item.path.as_str() > cursor)
            .unwrap_or(items.len()),
        None => 0,
    };
    let end = (start + limit).min(items.len());
    let slice = items[start..end].to_vec();
    let next = if end < items.len() {
        slice.last().map(|item| item.path.clone())
    } else {
        None
    };
    (slice, next)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use axum::body::to_bytes;
    use axum::response::IntoResponse;
    use pico_core::{
        ExecRequest, ExecResponse, FileReadResponse, Result, SandboxInfo, SandboxSpec, SshInfo,
        TaskEvent, TaskInfo, TaskRequest,
    };
    use tokio::sync::broadcast;

    use super::*;

    struct FilesMock {
        files: Mutex<Vec<FileInfo>>,
    }

    #[async_trait]
    impl pico_core::SandboxService for FilesMock {
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
            unimplemented!()
        }

        async fn file_read(&self, _: &str, path: &str) -> Result<FileReadResponse> {
            Ok(FileReadResponse {
                path: path.into(),
                content: "hi".into(),
                size: 2,
                modified_at: "x".into(),
            })
        }

        async fn file_write(&self, _: &str, req: FileWriteRequest) -> Result<FileInfo> {
            Ok(FileInfo {
                path: req.path,
                size: req.content.len() as u64,
                is_dir: false,
                modified_at: "x".into(),
            })
        }

        async fn file_list(&self, _: &str, _: &str, _: bool) -> Result<Vec<FileInfo>> {
            Ok(self.files.lock().unwrap().clone())
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
    async fn get_file_path_returns_read_response() {
        let state: AppState = Arc::new(FilesMock {
            files: Mutex::new(vec![]),
        });
        let resp = get(
            State(state),
            Path("sbx_x".into()),
            Query(FileGetQuery {
                path: Some("a.txt".into()),
                dir: None,
                recursive: false,
                limit: None,
                cursor: None,
            }),
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn get_dir_paginates() {
        let files: Vec<FileInfo> = (0..3)
            .map(|index| FileInfo {
                path: format!("file_{index}.txt"),
                size: 0,
                is_dir: false,
                modified_at: "x".into(),
            })
            .collect();
        let state: AppState = Arc::new(FilesMock {
            files: Mutex::new(files),
        });
        let resp = get(
            State(state),
            Path("sbx_x".into()),
            Query(FileGetQuery {
                path: None,
                dir: Some(".".into()),
                recursive: false,
                limit: Some(2),
                cursor: None,
            }),
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["items"].as_array().unwrap().len(), 2);
        assert!(value["next_cursor"].as_str().is_some());
    }

    #[tokio::test]
    async fn get_without_path_or_dir_is_400() {
        let state: AppState = Arc::new(FilesMock {
            files: Mutex::new(vec![]),
        });
        let err = get(
            State(state),
            Path("sbx_x".into()),
            Query(FileGetQuery {
                path: None,
                dir: None,
                recursive: false,
                limit: None,
                cursor: None,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.into_response().status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn put_returns_200() {
        let state: AppState = Arc::new(FilesMock {
            files: Mutex::new(vec![]),
        });
        let resp = put(
            State(state),
            Path("sbx_x".into()),
            Json(FileWriteRequest {
                path: "a.txt".into(),
                content: "data".into(),
                append: false,
            }),
        )
        .await
        .unwrap();
        assert_eq!(resp.0, StatusCode::OK);
    }
}

//! Task lifecycle and SSE handlers for the v1 platform API.

use std::convert::Infallible;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use pico_core::{TaskEvent, TaskInfo, TaskRequest, TaskState};
use tokio::sync::{broadcast, mpsc};
use tokio::time::{Duration, timeout};
use tokio_stream::wrappers::ReceiverStream;

use crate::error::AppError;
use crate::state::AppState;

/// Starts a new task for the sandbox and returns its initial status.
pub(crate) async fn start(
    State(agent): State<AppState>,
    Path(sandbox_id): Path<String>,
    Json(req): Json<TaskRequest>,
) -> Result<(StatusCode, Json<TaskInfo>), AppError> {
    let info = agent.task_start(&sandbox_id, req).await?;
    Ok((StatusCode::ACCEPTED, Json(info)))
}

/// Returns the current status snapshot for a task.
pub(crate) async fn get_one(
    State(agent): State<AppState>,
    Path((sandbox_id, task_id)): Path<(String, String)>,
) -> Result<Json<TaskInfo>, AppError> {
    Ok(Json(agent.task_get(&sandbox_id, &task_id).await?))
}

/// Requests cancellation for a running task.
pub(crate) async fn cancel(
    State(agent): State<AppState>,
    Path((sandbox_id, task_id)): Path<(String, String)>,
) -> Result<StatusCode, AppError> {
    agent.task_cancel(&sandbox_id, &task_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Streams task events over SSE until the task reaches a terminal state.
pub(crate) async fn events(
    State(agent): State<AppState>,
    Path((sandbox_id, task_id)): Path<(String, String)>,
) -> Result<Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>>, AppError> {
    let rx = agent.task_subscribe(&sandbox_id, &task_id)?;
    Ok(Sse::new(task_event_stream(rx)).keep_alive(KeepAlive::new()))
}

/// Adapts task broadcast events into an SSE response stream with deterministic shutdown.
fn task_event_stream(
    mut rx: broadcast::Receiver<TaskEvent>,
) -> ReceiverStream<Result<Event, Infallible>> {
    let (tx, stream) = mpsc::channel(16);
    tokio::spawn(async move {
        let mut after_terminal_status = false;
        loop {
            let event = if after_terminal_status {
                match timeout(Duration::from_millis(100), rx.recv()).await {
                    Ok(Ok(event)) => event,
                    Ok(Err(broadcast::error::RecvError::Lagged(_))) => continue,
                    Ok(Err(broadcast::error::RecvError::Closed)) | Err(_) => break,
                }
            } else {
                match rx.recv().await {
                    Ok(event) => event,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            };

            let terminal_status = matches!(
                event,
                TaskEvent::Status {
                    state: TaskState::Completed | TaskState::Failed | TaskState::Cancelled,
                    ..
                }
            );
            let result_event = matches!(event, TaskEvent::Result { .. });
            if tx.send(Ok(serialize_sse_event(event))).await.is_err() {
                break;
            }

            if result_event {
                break;
            }
            if terminal_status {
                after_terminal_status = true;
            }
        }
    });
    ReceiverStream::new(stream)
}

/// Serializes one task event into the SSE `data:` payload.
fn serialize_sse_event(event: TaskEvent) -> Event {
    let data = match serde_json::to_string(&event) {
        Ok(data) => data,
        Err(err) => {
            tracing::error!(error = %err, "failed to serialize task event");
            String::new()
        }
    };
    Event::default().data(data)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use pico_core::{
        ExecRequest, ExecResponse, FileInfo, FileReadResponse, FileWriteRequest, Result,
        SandboxInfo, SandboxSpec, SshInfo, TaskEvent, TaskState,
    };
    use tokio::sync::broadcast;
    use tokio::time::{Duration, timeout};
    use tokio_stream::StreamExt;

    use super::*;

    struct TasksMock {
        events: broadcast::Sender<TaskEvent>,
    }

    #[async_trait]
    impl pico_core::SandboxService for TasksMock {
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
            Ok(task_info(TaskState::Pending))
        }

        async fn task_get(&self, _: &str, _: &str) -> Result<TaskInfo> {
            Ok(task_info(TaskState::Completed))
        }

        async fn task_cancel(&self, _: &str, _: &str) -> Result<()> {
            Ok(())
        }

        fn task_subscribe(&self, _: &str, _: &str) -> Result<broadcast::Receiver<TaskEvent>> {
            Ok(self.events.subscribe())
        }

        async fn ssh_info(&self, _: &str) -> Result<SshInfo> {
            unimplemented!()
        }
    }

    fn state() -> AppState {
        let (events, _rx) = broadcast::channel(8);
        Arc::new(TasksMock { events })
    }

    fn task_info(state: TaskState) -> TaskInfo {
        TaskInfo {
            id: "task_test".into(),
            state,
            started_at: None,
            ended_at: None,
            exit_code: None,
            error: None,
        }
    }

    #[tokio::test]
    async fn start_returns_202() {
        let resp = start(
            State(state()),
            Path("sbx_test".into()),
            Json(TaskRequest {
                prompt: "hello".into(),
                agent: "echo".into(),
                model: None,
                timeout_secs: Some(5),
            }),
        )
        .await
        .unwrap();

        assert_eq!(resp.0, StatusCode::ACCEPTED);
        assert_eq!(resp.1.0.id, "task_test");
    }

    #[tokio::test]
    async fn get_one_returns_task_info() {
        let resp = get_one(
            State(state()),
            Path(("sbx_test".into(), "task_test".into())),
        )
        .await
        .unwrap();

        assert_eq!(resp.0.state, TaskState::Completed);
    }

    #[tokio::test]
    async fn cancel_returns_204() {
        let status = cancel(
            State(state()),
            Path(("sbx_test".into(), "task_test".into())),
        )
        .await
        .unwrap();

        assert_eq!(status, StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn events_returns_sse_stream() {
        let result = events(
            State(state()),
            Path(("sbx_test".into(), "task_test".into())),
        )
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn task_event_stream_closes_after_terminal_status_and_result() {
        let (tx, rx) = broadcast::channel(8);
        let mut stream = task_event_stream(rx);
        tx.send(TaskEvent::Status {
            ts: "x".into(),
            state: TaskState::Completed,
        })
        .unwrap();
        tx.send(TaskEvent::Result {
            ts: "x".into(),
            exit_code: 0,
        })
        .unwrap();

        assert!(stream.next().await.is_some());
        assert!(stream.next().await.is_some());
        assert!(
            timeout(Duration::from_secs(1), stream.next())
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn task_event_stream_closes_after_cancelled_status_without_result() {
        let (tx, rx) = broadcast::channel(8);
        let mut stream = task_event_stream(rx);
        tx.send(TaskEvent::Status {
            ts: "x".into(),
            state: TaskState::Cancelled,
        })
        .unwrap();

        assert!(stream.next().await.is_some());
        assert!(
            timeout(Duration::from_secs(1), stream.next())
                .await
                .unwrap()
                .is_none()
        );
    }
}

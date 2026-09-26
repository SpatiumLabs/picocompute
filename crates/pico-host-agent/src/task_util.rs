use std::sync::Arc;

use pico_core::{TaskEvent, TaskState};
use tokio::io::{AsyncBufReadExt, BufReader};

use crate::task_registry;

pub(crate) async fn cancel_task_entry(entry: &Arc<task_registry::TaskEntry>) {
    entry.cancel.cancel();
    let mut info = entry.info.lock().await;
    if info.state.is_terminal() {
        return;
    }
    info.state = TaskState::Cancelled;
    info.ended_at = Some(pico_core::now_iso());
    drop(info);
    let _ = entry.events.send(TaskEvent::Status {
        ts: pico_core::now_iso(),
        state: TaskState::Cancelled,
    });
}

#[derive(Debug)]
pub(crate) enum TaskEnd {
    Exit(i32),
    Cancelled,
    Timeout,
    Error(String),
}

pub(crate) enum StreamKind {
    Stdout,
    Stderr,
}

pub(crate) fn stream_task_output<T>(
    stream: T,
    events: tokio::sync::broadcast::Sender<TaskEvent>,
    kind: StreamKind,
) -> tokio::task::JoinHandle<()>
where
    T: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut lines = BufReader::new(stream).lines();
        loop {
            match lines.next_line().await {
                Ok(Some(line)) => {
                    let event = match kind {
                        StreamKind::Stdout => TaskEvent::Stdout {
                            ts: pico_core::now_iso(),
                            data: line,
                        },
                        StreamKind::Stderr => TaskEvent::Stderr {
                            ts: pico_core::now_iso(),
                            data: line,
                        },
                    };
                    let _ = events.send(event);
                }
                Ok(None) => return,
                Err(err) => {
                    let _ = events.send(TaskEvent::Error {
                        ts: pico_core::now_iso(),
                        message: format!("stream read failed: {err}"),
                    });
                    return;
                }
            }
        }
    })
}

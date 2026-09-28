//! Job-scoped pause and resume handlers.
//!
//! The control plane pauses a whole job (a set of sandboxes) with one
//! envelope. The handlers validate that the path job id matches the body,
//! then fan out through the host job path so every member keeps fencing,
//! policy-epoch, deadline, and audit handling.

use axum::Json;
use axum::extract::{Path, State};
use pico_core::{JobOutcome, JobPauseSignal, JobResumeSignal, SandboxError};

use crate::error::AppError;
use crate::state::AppState;

fn ensure_job_match(path_job: &str, body_job: &str) -> Result<(), AppError> {
    if path_job != body_job {
        return Err(SandboxError::BadRequest(format!(
            "job id mismatch: path {path_job} != body {body_job}"
        ))
        .into());
    }
    Ok(())
}

pub(crate) async fn pause_job(
    State(agent): State<AppState>,
    Path(job_id): Path<String>,
    Json(signal): Json<JobPauseSignal>,
) -> Result<Json<JobOutcome>, AppError> {
    ensure_job_match(&job_id, &signal.job_id)?;
    let outcome = agent.pause_job(signal).await?;
    Ok(Json(outcome))
}

pub(crate) async fn resume_job(
    State(agent): State<AppState>,
    Path(job_id): Path<String>,
    Json(signal): Json<JobResumeSignal>,
) -> Result<Json<JobOutcome>, AppError> {
    ensure_job_match(&job_id, &signal.job_id)?;
    let outcome = agent.resume_job(signal).await?;
    Ok(Json(outcome))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn job_id_mismatch_is_bad_request() {
        let err = ensure_job_match("job_a", "job_b").unwrap_err();
        use axum::response::IntoResponse;
        assert_eq!(
            err.into_response().status(),
            axum::http::StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn pause_job_rejects_mismatched_envelope() {
        use std::collections::HashMap;
        use std::sync::Mutex;
        use tokio::sync::broadcast;

        struct Mock;
        #[async_trait::async_trait]
        impl pico_core::SandboxService for Mock {
            async fn create(
                &self,
                _: pico_core::SandboxSpec,
            ) -> pico_core::Result<pico_core::SandboxInfo> {
                unimplemented!()
            }
            async fn list(
                &self,
                _: usize,
                _: Option<String>,
            ) -> pico_core::Result<(Vec<pico_core::SandboxInfo>, Option<String>)> {
                unimplemented!()
            }
            async fn get(&self, _: &str) -> pico_core::Result<pico_core::SandboxInfo> {
                unimplemented!()
            }
            async fn destroy(&self, _: &str) -> pico_core::Result<()> {
                unimplemented!()
            }
            async fn purge(&self, _: &str) -> pico_core::Result<()> {
                unimplemented!()
            }
            async fn stop(&self, _: &str) -> pico_core::Result<()> {
                unimplemented!()
            }
            async fn keepalive(&self, _: &str) -> pico_core::Result<()> {
                unimplemented!()
            }
            async fn exec(
                &self,
                _: &str,
                _: pico_core::ExecRequest,
            ) -> pico_core::Result<pico_core::ExecResponse> {
                unimplemented!()
            }
            async fn file_read(
                &self,
                _: &str,
                _: &str,
            ) -> pico_core::Result<pico_core::FileReadResponse> {
                unimplemented!()
            }
            async fn file_write(
                &self,
                _: &str,
                _: pico_core::FileWriteRequest,
            ) -> pico_core::Result<pico_core::FileInfo> {
                unimplemented!()
            }
            async fn file_list(
                &self,
                _: &str,
                _: &str,
                _: bool,
            ) -> pico_core::Result<Vec<pico_core::FileInfo>> {
                unimplemented!()
            }
            async fn task_start(
                &self,
                _: &str,
                _: pico_core::TaskRequest,
            ) -> pico_core::Result<pico_core::TaskInfo> {
                unimplemented!()
            }
            async fn task_get(&self, _: &str, _: &str) -> pico_core::Result<pico_core::TaskInfo> {
                unimplemented!()
            }
            async fn task_cancel(&self, _: &str, _: &str) -> pico_core::Result<()> {
                unimplemented!()
            }
            fn task_subscribe(
                &self,
                _: &str,
                _: &str,
            ) -> pico_core::Result<broadcast::Receiver<pico_core::TaskEvent>> {
                unimplemented!()
            }
            async fn ssh_info(&self, _: &str) -> pico_core::Result<pico_core::SshInfo> {
                unimplemented!()
            }
        }

        let state: AppState = Arc::new(Mock);
        let signal = JobPauseSignal {
            job_id: "job_body".into(),
            sandbox_ids: vec!["sbx_abc123".into()],
            fencing_token: pico_core::FencingToken {
                epoch: 1,
                sequence: 1,
            },
            policy_epoch: 1,
            deadline_secs: 60,
            reason: "test".into(),
        };
        let err = pause_job(State(state), Path("job_path".into()), Json(signal))
            .await
            .unwrap_err();
        use axum::response::IntoResponse;
        assert_eq!(
            err.into_response().status(),
            axum::http::StatusCode::BAD_REQUEST
        );
        let _ = HashMap::<String, String>::new();
        let _ = Mutex::new(());
    }
}

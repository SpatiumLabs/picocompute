//! Job-scoped pause and resume handlers.
//!
//! The control plane pauses a whole job (a set of sandboxes) with one
//! envelope. The handlers validate that the path job id matches the body,
//! then fan out through the host job path so every member keeps fencing,
//! policy-epoch, deadline, and audit handling.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
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

/// Status for a job outcome.
///
/// A bulk signal that only partially applied must not read as success to a
/// caller that only checks the HTTP status, so both `pause` and `resume`
/// return `207` when any member failed.
///
/// A pause additionally returns `207` when every member suspended but
/// nothing was actually reclaimed (`reclaim_applied: false` on every
/// member): the sandboxes are correctly `Suspended`, but preemptible
/// capacity was not freed, which is not a successful reclaim. Resume
/// ignores the reclaim flag because restoring does not reclaim.
fn outcome_status(outcome: &JobOutcome, is_pause: bool) -> StatusCode {
    let reclaim_incomplete = is_pause && !outcome.members.is_empty() && !outcome.any_reclaimed();
    if outcome.all_succeeded() && !reclaim_incomplete {
        StatusCode::OK
    } else {
        StatusCode::MULTI_STATUS
    }
}

pub(crate) async fn pause_job(
    State(agent): State<AppState>,
    Path(job_id): Path<String>,
    Json(signal): Json<JobPauseSignal>,
) -> Result<(StatusCode, Json<JobOutcome>), AppError> {
    ensure_job_match(&job_id, &signal.job_id)?;
    let outcome = agent.pause_job(signal).await?;
    let status = outcome_status(&outcome, true);
    Ok((status, Json(outcome)))
}

pub(crate) async fn resume_job(
    State(agent): State<AppState>,
    Path(job_id): Path<String>,
    Json(signal): Json<JobResumeSignal>,
) -> Result<(StatusCode, Json<JobOutcome>), AppError> {
    ensure_job_match(&job_id, &signal.job_id)?;
    let outcome = agent.resume_job(signal).await?;
    let status = outcome_status(&outcome, false);
    Ok((status, Json(outcome)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pico_core::{JobMemberOutcome, ReclaimStrategy};
    use std::sync::Arc;

    fn outcome(all_ok: bool, reclaim_applied: bool) -> JobOutcome {
        JobOutcome {
            job_id: "job_x".into(),
            members: vec![JobMemberOutcome {
                sandbox_id: "sbx_a".into(),
                succeeded: all_ok,
                strategy: ReclaimStrategy::ContainerSwapReclaim,
                reclaim_applied,
                message: if all_ok {
                    String::new()
                } else {
                    "suspend timed out".into()
                },
            }],
        }
    }

    #[test]
    fn all_succeeded_with_reclaim_returns_ok() {
        assert_eq!(outcome_status(&outcome(true, true), true), StatusCode::OK);
    }

    #[test]
    fn partial_failure_returns_multi_status() {
        assert_eq!(
            outcome_status(&outcome(false, false), true),
            StatusCode::MULTI_STATUS
        );
    }

    #[test]
    fn pause_without_reclaim_returns_multi_status() {
        // Every member suspended but nothing was reclaimed: not a
        // successful reclaim, so a status-only caller must see it.
        let outcome = outcome(true, false);
        assert!(outcome.all_succeeded());
        assert!(!outcome.any_reclaimed());
        assert_eq!(outcome_status(&outcome, true), StatusCode::MULTI_STATUS);
    }

    #[test]
    fn resume_ignores_reclaim_flag() {
        // Restoring does not reclaim, so a resume that never reclaims is
        // still a success.
        assert_eq!(outcome_status(&outcome(true, false), false), StatusCode::OK);
    }

    #[test]
    fn job_id_mismatch_is_bad_request() {
        let err = ensure_job_match("job_a", "job_b").unwrap_err();
        use axum::response::IntoResponse;
        assert_eq!(
            err.into_response().status(),
            axum::http::StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn pause_job_rejects_mismatched_envelope() {
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
            tenant_id: None,
        };
        let err = pause_job(State(state), Path("job_path".into()), Json(signal))
            .await
            .unwrap_err();
        use axum::response::IntoResponse;
        assert_eq!(
            err.into_response().status(),
            axum::http::StatusCode::BAD_REQUEST
        );
    }
}

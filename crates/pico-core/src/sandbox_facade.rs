//! Public sandbox management surface consumed by the platform API.
//!
//! `SandboxFacade` is the small lifecycle contract between API-style consumers
//! and a sandbox backend. Data-plane capabilities live on `SandboxService`,
//! which is the aggregate contract used by the HTTP adapter. Host-only control
//! operations (prepare, fenced boot, drain, host inventory) stay behind
//! `HostControl`.

use async_trait::async_trait;
use tokio::sync::broadcast;

use crate::{
    AccessLease, ExecRequest, ExecResponse, FileInfo, FileReadResponse, FileWriteRequest,
    JobOutcome, JobPauseSignal, JobResumeSignal, LeaseAction, LeaseScope, PortForwardEndpoint,
    PortForwardRequest, PortForwardResponse, Result, SandboxError, SandboxInfo, SandboxSpec,
    SshInfo, TaskEvent, TaskInfo, TaskRequest,
};

/// Narrow control contract for lifecycle consumers.
///
/// The API lifecycle view implements this seam over a complete
/// [`SandboxService`], and a backend that only needs the common control
/// operations can implement it directly. Data-plane operations beyond the
/// shared exec call stay on [`SandboxService`] so a consumer that only manages
/// sandbox control does not depend on files, tasks, SSH, or ingress details.
#[async_trait]
pub trait SandboxFacade: Send + Sync {
    /// Creates a new sandbox from the given spec.
    async fn create(&self, spec: SandboxSpec) -> Result<SandboxInfo>;

    /// Returns a page of sandboxes sorted by id, plus the next cursor.
    async fn list(
        &self,
        limit: usize,
        cursor: Option<String>,
    ) -> Result<(Vec<SandboxInfo>, Option<String>)>;

    /// Returns the current info for one sandbox.
    async fn get(&self, id: &str) -> Result<SandboxInfo>;

    /// Force-destroys a sandbox and releases its host resources.
    ///
    /// Implementations must reject a terminal record before destructive work
    /// begins. Use [`crate::ensure_destroy_precondition`] at the adapter seam.
    async fn destroy(&self, id: &str) -> Result<()>;

    /// Purges the remaining state of a sandbox after `stop`.
    ///
    /// Implementations must reject a non-`Stopped` sandbox before destructive
    /// work begins. Use [`crate::ensure_purge_precondition`] at the adapter
    /// seam.
    async fn purge(&self, id: &str) -> Result<()>;

    /// Stops a running sandbox without purging its host-side record.
    ///
    /// Repeated calls on `Stopped` are idempotent. Other states are rejected
    /// before fencing or runtime side effects.
    async fn stop(&self, id: &str) -> Result<()>;

    /// Bumps the idle timeout so the sandbox is not reaped.
    async fn keepalive(&self, id: &str) -> Result<()>;

    /// Runs a command inside an existing sandbox.
    async fn exec(&self, id: &str, req: ExecRequest) -> Result<ExecResponse>;

    /// Suspends a running sandbox.
    async fn suspend(&self, id: &str) -> Result<()>;

    /// Resumes a suspended sandbox.
    async fn resume(&self, id: &str) -> Result<()>;
}

/// Complete API-facing sandbox service.
///
/// This aggregate is intentionally separate from [`SandboxFacade`]. The
/// narrow facade is the lifecycle seam; this trait is the data-plane adapter
/// used by the HTTP layer. Optional operations fail closed with
/// [`SandboxError::NotImplemented`] instead of silently succeeding.
#[async_trait]
pub trait SandboxService: Send + Sync {
    /// Creates a new sandbox from the given spec.
    async fn create(&self, spec: SandboxSpec) -> Result<SandboxInfo>;

    /// Returns a page of sandboxes sorted by id, plus the next cursor.
    async fn list(
        &self,
        limit: usize,
        cursor: Option<String>,
    ) -> Result<(Vec<SandboxInfo>, Option<String>)>;

    /// Returns the current info for one sandbox.
    async fn get(&self, id: &str) -> Result<SandboxInfo>;

    /// Force-destroys a sandbox and releases its host resources.
    ///
    /// Implementations must reject a terminal record before destructive work
    /// begins. Use [`crate::ensure_destroy_precondition`] at the adapter seam.
    async fn destroy(&self, id: &str) -> Result<()>;

    /// Purges the remaining state of a sandbox after `stop`.
    ///
    /// Implementations must reject a non-`Stopped` sandbox before destructive
    /// work begins. Use [`crate::ensure_purge_precondition`] at the adapter
    /// seam.
    async fn purge(&self, id: &str) -> Result<()>;

    /// Stops a running sandbox without purging its host-side record.
    ///
    /// Repeated calls on `Stopped` are idempotent. Other states are rejected
    /// before fencing or runtime side effects.
    async fn stop(&self, id: &str) -> Result<()>;

    /// Bumps the idle timeout so the sandbox is not reaped.
    async fn keepalive(&self, id: &str) -> Result<()>;

    /// Runs a command inside an existing sandbox.
    async fn exec(&self, id: &str, req: ExecRequest) -> Result<ExecResponse>;

    /// Reads a file from the sandbox filesystem.
    async fn file_read(&self, id: &str, path: &str) -> Result<FileReadResponse>;

    /// Writes a file to the sandbox filesystem.
    async fn file_write(&self, id: &str, req: FileWriteRequest) -> Result<FileInfo>;

    /// Lists files under a directory in the sandbox.
    async fn file_list(&self, id: &str, dir: &str, recursive: bool) -> Result<Vec<FileInfo>>;

    /// Starts a background task in the sandbox.
    async fn task_start(&self, id: &str, req: TaskRequest) -> Result<TaskInfo>;

    /// Returns the current state of a task.
    async fn task_get(&self, id: &str, task_id: &str) -> Result<TaskInfo>;

    /// Cancels a running task.
    async fn task_cancel(&self, id: &str, task_id: &str) -> Result<()>;

    /// Subscribes to the event stream of a task.
    fn task_subscribe(&self, id: &str, task_id: &str) -> Result<broadcast::Receiver<TaskEvent>>;

    /// Returns SSH connection info for the sandbox.
    async fn ssh_info(&self, id: &str) -> Result<SshInfo>;

    /// Issues a signed access lease for a sandbox action.
    async fn issue_access_lease(
        &self,
        _sandbox_id: &str,
        _action: LeaseAction,
        _scope: LeaseScope,
    ) -> Result<AccessLease> {
        Err(SandboxError::NotImplemented(
            "access lease issuance is not implemented by this service",
        ))
    }

    /// Exposes a guest port on the host and returns the bound endpoint.
    async fn expose_port(
        &self,
        _id: &str,
        _req: PortForwardRequest,
    ) -> Result<PortForwardEndpoint> {
        Err(SandboxError::NotImplemented(
            "port forwarding is not implemented by this service",
        ))
    }

    /// Revokes a previously exposed port endpoint.
    async fn revoke_port(&self, _id: &str, _endpoint_id: &str) -> Result<PortForwardResponse> {
        Err(SandboxError::NotImplemented(
            "port forwarding is not implemented by this service",
        ))
    }

    /// Lists the currently exposed port endpoints of a sandbox.
    async fn list_ports(&self, _id: &str) -> Result<Vec<PortForwardEndpoint>> {
        Err(SandboxError::NotImplemented(
            "port forwarding is not implemented by this service",
        ))
    }

    /// Suspends a running sandbox.
    async fn suspend(&self, _id: &str) -> Result<()> {
        Err(SandboxError::NotImplemented(
            "suspend is not implemented by this service",
        ))
    }

    /// Resumes a suspended sandbox.
    async fn resume(&self, _id: &str) -> Result<()> {
        Err(SandboxError::NotImplemented(
            "resume is not implemented by this service",
        ))
    }

    /// Pauses a whole job with per-backend reclaim behind the suspend contract.
    ///
    /// The default fails closed so backends without job support cannot
    /// silently accept a bulk pause.
    async fn pause_job(&self, _signal: JobPauseSignal) -> Result<JobOutcome> {
        Err(SandboxError::NotImplemented(
            "job pause is not implemented by this service",
        ))
    }

    /// Resumes a whole job with fresh authority behind the suspend contract.
    async fn resume_job(&self, _signal: JobResumeSignal) -> Result<JobOutcome> {
        Err(SandboxError::NotImplemented(
            "job resume is not implemented by this service",
        ))
    }
}

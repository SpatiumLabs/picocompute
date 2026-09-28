//! Host-only control surface, plus the `HostAgent` trait implementations.
//!
//! The sandbox operations consumed by the platform API live on
//! [`pico_core::SandboxService`]. This module keeps the host-only control
//! operations (prepare, fenced boot, drain, host inventory) that only the
//! host-agent's own RPC surface exposes.

use async_trait::async_trait;
use pico_core::{
    ExecRequest, ExecResponse, FileInfo, FileReadResponse, FileWriteRequest, JobOutcome,
    JobPauseSignal, JobResumeSignal, PortForwardEndpoint, PortForwardRequest, PortForwardResponse,
    Result, SandboxError, SandboxInfo, SandboxSpec, SshInfo, TaskEvent, TaskInfo, TaskRequest,
};
use tokio::sync::broadcast;

use crate::HostAgent;
use crate::boot::{BootCommand, BootReport};
use crate::health::HostHealth;
use crate::identity::HostInventory;

/// Host-level control operations exposed only on the host's own RPC surface
/// (`/rpc/v1/*`). The platform API never calls these; keeping them off
/// [`SandboxService`] lets API consumers depend on core contracts alone.
///
/// Lean implementations (`StubAgent`, test doubles) rely on the
/// `NotImplemented` defaults for the lifecycle operations they do not drive.
#[async_trait]
pub trait HostControl: Send + Sync {
    /// Prepares a sandbox without booting it.
    async fn prepare(&self, _spec: SandboxSpec) -> Result<SandboxInfo> {
        Err(SandboxError::NotImplemented(
            "prepare is not implemented by this host",
        ))
    }

    /// Runs the fenced boot lifecycle for a prepared sandbox.
    async fn boot_with_context(&self, _command: BootCommand) -> Result<BootReport> {
        Err(SandboxError::NotImplemented(
            "fenced boot is not implemented by this host",
        ))
    }

    /// Forks a sandbox into a new sandbox from the given spec.
    async fn fork(&self, id: &str, new_spec: SandboxSpec) -> Result<SandboxInfo> {
        let _ = (id, new_spec);
        Err(SandboxError::NotImplemented(
            "fork is not implemented by this host",
        ))
    }

    /// Returns the host's current health snapshot, including sandboxd
    /// liveness. The host reports degraded until sandboxd is reachable and
    /// has completed reconciliation (ADR-0011 §4).
    async fn health(&self) -> HostHealth;

    /// Returns the host's identity and capacity inventory.
    ///
    /// Async because scheduler capacity sums live sandbox allocations.
    async fn inventory(&self) -> HostInventory;

    /// Returns host-level statistics as JSON.
    async fn stats(&self) -> serde_json::Value {
        serde_json::json!({"sandbox_count": 0})
    }

    /// Drains the host: stops admitting new sandboxes and tears down state.
    async fn drain(&self) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
impl pico_core::SandboxService for HostAgent {
    async fn create(&self, spec: SandboxSpec) -> Result<SandboxInfo> {
        self.create_sandbox(spec).await
    }

    async fn list(
        &self,
        limit: usize,
        cursor: Option<String>,
    ) -> Result<(Vec<SandboxInfo>, Option<String>)> {
        self.list_sandboxes_paginated(limit, cursor).await
    }

    async fn get(&self, id: &str) -> Result<SandboxInfo> {
        self.get_sandbox(id).await
    }

    async fn destroy(&self, id: &str) -> Result<()> {
        HostAgent::destroy(self, id).await
    }

    async fn purge(&self, id: &str) -> Result<()> {
        HostAgent::purge(self, id).await
    }

    async fn stop(&self, id: &str) -> Result<()> {
        HostAgent::stop(self, id).await
    }

    async fn keepalive(&self, id: &str) -> Result<()> {
        HostAgent::keepalive(self, id).await
    }

    async fn exec(&self, id: &str, req: ExecRequest) -> Result<ExecResponse> {
        HostAgent::exec(self, id, req).await
    }

    async fn file_read(&self, id: &str, path: &str) -> Result<FileReadResponse> {
        HostAgent::file_read(self, id, path).await
    }

    async fn file_write(&self, id: &str, req: FileWriteRequest) -> Result<FileInfo> {
        HostAgent::file_write(self, id, req).await
    }

    async fn file_list(&self, id: &str, dir: &str, recursive: bool) -> Result<Vec<FileInfo>> {
        HostAgent::file_list(self, id, dir, recursive).await
    }

    async fn task_start(&self, id: &str, req: TaskRequest) -> Result<TaskInfo> {
        HostAgent::task_start(self, id, req).await
    }

    async fn task_get(&self, id: &str, task_id: &str) -> Result<TaskInfo> {
        HostAgent::task_get(self, id, task_id).await
    }

    async fn task_cancel(&self, id: &str, task_id: &str) -> Result<()> {
        HostAgent::task_cancel(self, id, task_id).await
    }

    fn task_subscribe(&self, id: &str, task_id: &str) -> Result<broadcast::Receiver<TaskEvent>> {
        let entry = self.task_entry_for_sandbox(id, task_id)?;
        Ok(entry.events.subscribe())
    }

    async fn ssh_info(&self, id: &str) -> Result<SshInfo> {
        HostAgent::ssh_info(self, id).await
    }

    async fn expose_port(&self, id: &str, req: PortForwardRequest) -> Result<PortForwardEndpoint> {
        self.expose_port(id, req).await
    }

    async fn revoke_port(&self, id: &str, endpoint_id: &str) -> Result<PortForwardResponse> {
        self.revoke_port(id, endpoint_id).await
    }

    async fn list_ports(&self, id: &str) -> Result<Vec<PortForwardEndpoint>> {
        self.list_ports(id).await
    }

    async fn suspend(&self, id: &str) -> Result<()> {
        HostAgent::suspend(self, id).await
    }

    async fn resume(&self, id: &str) -> Result<()> {
        HostAgent::resume(self, id).await
    }

    async fn pause_job(&self, signal: JobPauseSignal) -> Result<JobOutcome> {
        HostAgent::pause_job(self, signal).await
    }

    async fn resume_job(&self, signal: JobResumeSignal) -> Result<JobOutcome> {
        HostAgent::resume_job(self, signal).await
    }
}

#[async_trait]
impl pico_core::SandboxFacade for HostAgent {
    async fn create(&self, spec: SandboxSpec) -> Result<SandboxInfo> {
        self.create_sandbox(spec).await
    }

    async fn list(
        &self,
        limit: usize,
        cursor: Option<String>,
    ) -> Result<(Vec<SandboxInfo>, Option<String>)> {
        self.list_sandboxes_paginated(limit, cursor).await
    }

    async fn get(&self, id: &str) -> Result<SandboxInfo> {
        self.get_sandbox(id).await
    }

    async fn destroy(&self, id: &str) -> Result<()> {
        HostAgent::destroy(self, id).await
    }

    async fn purge(&self, id: &str) -> Result<()> {
        HostAgent::purge(self, id).await
    }

    async fn stop(&self, id: &str) -> Result<()> {
        HostAgent::stop(self, id).await
    }

    async fn keepalive(&self, id: &str) -> Result<()> {
        HostAgent::keepalive(self, id).await
    }

    async fn exec(&self, id: &str, req: ExecRequest) -> Result<ExecResponse> {
        HostAgent::exec(self, id, req).await
    }

    async fn suspend(&self, id: &str) -> Result<()> {
        HostAgent::suspend(self, id).await
    }

    async fn resume(&self, id: &str) -> Result<()> {
        HostAgent::resume(self, id).await
    }
}

#[async_trait]
impl HostControl for HostAgent {
    async fn prepare(&self, spec: SandboxSpec) -> Result<SandboxInfo> {
        let _in_flight = self.track_create();
        self.prepare_sandbox(spec).await
    }

    async fn boot_with_context(&self, command: BootCommand) -> Result<BootReport> {
        let _in_flight = self.track_create();
        self.boot_sandbox(command).await
    }

    async fn fork(&self, id: &str, _new_spec: SandboxSpec) -> Result<SandboxInfo> {
        let _ = self.get_sandbox(id).await?;
        Err(SandboxError::NotImplemented(
            "fork is not implemented by the host agent",
        ))
    }

    async fn health(&self) -> HostHealth {
        HostAgent::health_with_gc(self).await
    }

    async fn inventory(&self) -> HostInventory {
        HostAgent::inventory(self).await
    }

    async fn stats(&self) -> serde_json::Value {
        HostAgent::stats(self).await
    }

    async fn drain(&self) -> Result<()> {
        HostAgent::drain(self).await
    }
}

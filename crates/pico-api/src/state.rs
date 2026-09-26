//! Shared application state types exposed to API handlers.

use std::sync::Arc;

use async_trait::async_trait;
use pico_core::{
    ExecRequest, ExecResponse, Result, SandboxFacade, SandboxInfo, SandboxService, SandboxSpec,
};

/// App state is one shared service object. All handlers depend on core
/// contracts, not on a concrete host agent, so unit tests can substitute a
/// mock and the API crate never imports host-only control operations.
pub(crate) type AppState = Arc<dyn SandboxService>;

pub(crate) struct LifecycleView<'a> {
    service: &'a dyn SandboxService,
}

#[async_trait]
impl SandboxFacade for LifecycleView<'_> {
    async fn create(&self, spec: SandboxSpec) -> Result<SandboxInfo> {
        self.service.create(spec).await
    }

    async fn list(
        &self,
        limit: usize,
        cursor: Option<String>,
    ) -> Result<(Vec<SandboxInfo>, Option<String>)> {
        self.service.list(limit, cursor).await
    }

    async fn get(&self, id: &str) -> Result<SandboxInfo> {
        self.service.get(id).await
    }

    async fn destroy(&self, id: &str) -> Result<()> {
        self.service.destroy(id).await
    }

    async fn purge(&self, id: &str) -> Result<()> {
        self.service.purge(id).await
    }

    async fn stop(&self, id: &str) -> Result<()> {
        self.service.stop(id).await
    }

    async fn keepalive(&self, id: &str) -> Result<()> {
        self.service.keepalive(id).await
    }

    async fn exec(&self, id: &str, req: ExecRequest) -> Result<ExecResponse> {
        self.service.exec(id, req).await
    }

    async fn suspend(&self, id: &str) -> Result<()> {
        self.service.suspend(id).await
    }

    async fn resume(&self, id: &str) -> Result<()> {
        self.service.resume(id).await
    }
}

/// Returns the narrow lifecycle view used by lifecycle handlers.
///
/// The service object also carries data-plane capabilities, but lifecycle
/// handlers cross only the small facade seam.
pub(crate) fn lifecycle(agent: &AppState) -> LifecycleView<'_> {
    LifecycleView {
        service: agent.as_ref(),
    }
}

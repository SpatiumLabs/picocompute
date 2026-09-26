//! Remote Firecracker guest-agent adapter for host-side development.

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use pico_core::runtime::{
    BackendCapabilities, BackendCapability, BackendHealth, BackendMetadata, BackendResult,
    BackendStats, CleanupReport, DiagnosticBundle, ForkResult, GuestTransport, PreparedSandbox,
    RuntimeBackend,
};
use pico_core::{
    BackendError, BackendOperation, ExecRequest, ExecResponse, NonReadyReason, SandboxConfig,
    SandboxState,
};
use pico_guest_protocol::GuestSession;

use crate::guest_agent;

#[derive(Debug, Clone)]
pub struct RemoteFirecrackerConfig {
    pub guest_agent_addr: SocketAddr,
    pub ssh_username: String,
    pub ssh_home_dir: String,
}

impl RemoteFirecrackerConfig {
    #[must_use]
    pub fn detect_defaults() -> Self {
        let ssh_username =
            std::env::var("PICO_REMOTE_SSH_USERNAME").unwrap_or_else(|_| "root".into());
        let default_ssh_home_dir = if ssh_username == "root" {
            "/root".into()
        } else {
            format!("/home/{ssh_username}")
        };
        Self {
            guest_agent_addr: std::env::var("PICO_GUEST_AGENT_ADDR")
                .unwrap_or_else(|_| "127.0.0.1:9999".into())
                .parse()
                .expect("PICO_GUEST_AGENT_ADDR must be a socket address"),
            ssh_username,
            ssh_home_dir: std::env::var("PICO_REMOTE_SSH_HOME").unwrap_or(default_ssh_home_dir),
        }
    }
}

pub struct RemoteFirecrackerAdapter {
    config: Arc<Mutex<Option<SandboxConfig>>>,
    state: Arc<Mutex<SandboxState>>,
    remote_config: RemoteFirecrackerConfig,
    guest_session: Arc<Mutex<Option<GuestSession<TcpStream>>>>,
}

impl Default for RemoteFirecrackerAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl RemoteFirecrackerAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: Arc::new(Mutex::new(None)),
            state: Arc::new(Mutex::new(SandboxState::Pending)),
            remote_config: RemoteFirecrackerConfig::detect_defaults(),
            guest_session: Arc::new(Mutex::new(None)),
        }
    }

    #[must_use]
    pub fn with_config(remote_config: RemoteFirecrackerConfig) -> Self {
        Self {
            config: Arc::new(Mutex::new(None)),
            state: Arc::new(Mutex::new(SandboxState::Pending)),
            remote_config,
            guest_session: Arc::new(Mutex::new(None)),
        }
    }

    async fn sandbox_id(&self) -> String {
        self.config
            .lock()
            .await
            .as_ref()
            .map(|c| c.id.clone())
            .unwrap_or_else(|| "unprepared".into())
    }
}

#[async_trait]
impl RuntimeBackend for RemoteFirecrackerAdapter {
    fn metadata(&self) -> BackendMetadata {
        BackendMetadata {
            runtime: pico_core::RuntimeType::RemoteFirecracker,
            version: env!("CARGO_PKG_VERSION").into(),
            capabilities: BackendCapabilities::from([
                BackendCapability::Boot,
                BackendCapability::GuestTransport,
                BackendCapability::GuestReadiness,
                BackendCapability::Exec,
                BackendCapability::Stats,
                BackendCapability::Health,
                BackendCapability::Diagnostics,
            ]),
        }
    }

    #[tracing::instrument(skip(self, config), fields(sandbox_id = %config.id))]
    async fn prepare(&self, config: &SandboxConfig) -> BackendResult<PreparedSandbox> {
        {
            let mut cfg = self.config.lock().await;
            *cfg = Some(config.clone());
        }
        {
            let mut state = self.state.lock().await;
            *state = SandboxState::Preparing;
        }
        tracing::info!(
            "Preparing remote Firecracker resources for sandbox {}",
            config.id
        );
        Ok(PreparedSandbox::default())
    }

    #[tracing::instrument(skip(self))]
    async fn boot(&self) -> BackendResult<()> {
        {
            let mut state = self.state.lock().await;
            if *state != SandboxState::Preparing {
                return Err(pico_core::BackendError::InvalidState {
                    operation: pico_core::BackendOperation::Boot,
                    expected: vec![SandboxState::Preparing],
                    actual: *state,
                });
            }
            *state = SandboxState::Booting;
        }

        if self.config.lock().await.is_none() {
            return Err(pico_core::BackendError::IncompleteSetup {
                operation: pico_core::BackendOperation::Boot,
                message: "sandbox must be prepared before boot".into(),
            });
        }

        Ok(())
    }

    async fn attach_transport(&self) -> BackendResult<GuestTransport> {
        let state = self.state().await?;
        if !matches!(state, SandboxState::Booting | SandboxState::Running) {
            return Err(pico_core::BackendError::InvalidState {
                operation: pico_core::BackendOperation::AttachTransport,
                expected: vec![SandboxState::Booting, SandboxState::Running],
                actual: state,
            });
        }
        // RemoteFirecracker is rejected for production; attach fails closed.
        Err(pico_core::BackendError::Unsupported {
            capability: pico_core::BackendCapability::GuestTransport,
        })
    }

    async fn wait_ready(&self, _transport: &GuestTransport) -> BackendResult<()> {
        Err(BackendError::NotReady {
            operation: BackendOperation::WaitReady,
            reason: NonReadyReason::Protocol,
            message: "remote Firecracker is rejected for production".into(),
        })
    }

    #[tracing::instrument(skip(self))]
    async fn destroy(&self) -> BackendResult<CleanupReport> {
        let mut state = self.state.lock().await;
        *state = SandboxState::Destroyed;
        Ok(CleanupReport::default())
    }

    async fn cleanup(&self) -> BackendResult<CleanupReport> {
        self.destroy().await
    }

    async fn fork(&self, _target: &SandboxConfig) -> BackendResult<ForkResult> {
        Err(pico_core::BackendError::Unsupported {
            capability: BackendCapability::Fork,
        })
    }

    async fn state(&self) -> BackendResult<SandboxState> {
        Ok(*self.state.lock().await)
    }

    #[tracing::instrument(skip(self, req), fields(command = %req.command))]
    async fn exec(&self, req: ExecRequest) -> BackendResult<ExecResponse> {
        tracing::info!(
            "Forwarding exec to remote Firecracker guest-agent: {:?}",
            req.command
        );
        let mut session_guard = self.guest_session.lock().await;
        if session_guard.is_none() {
            let sandbox_id = self.sandbox_id().await;
            let session =
                guest_agent::establish_session(self.remote_config.guest_agent_addr, &sandbox_id)
                    .await
                    .map_err(|err| BackendError::Failed {
                        operation: BackendOperation::Exec,
                        message: format!("establish guest session: {err}"),
                    })?;
            *session_guard = Some(session);
        }
        let session = session_guard.as_mut().ok_or_else(|| BackendError::Failed {
            operation: BackendOperation::Exec,
            message: "guest session unavailable after establishment".into(),
        })?;
        let result = guest_agent::session_exec(session, &req).await;
        match result {
            Ok(resp) => Ok(resp),
            Err(err) => {
                // A failed exec may leave stale frames buffered on the socket
                // and a possibly-dead connection; drop the session so the next
                // exec re-handshakes instead of consuming stale frames.
                *session_guard = None;
                Err(BackendError::Failed {
                    operation: BackendOperation::Exec,
                    message: err.to_string(),
                })
            }
        }
    }

    async fn stats(&self) -> BackendResult<BackendStats> {
        Ok(BackendStats {
            details: serde_json::json!({"state": self.state().await?.as_str()}),
            ..BackendStats::default()
        })
    }

    async fn health(&self) -> BackendResult<BackendHealth> {
        Ok(BackendHealth::ready())
    }

    async fn diagnostics(&self) -> BackendResult<DiagnosticBundle> {
        Ok(DiagnosticBundle {
            captured_at: pico_core::now_iso(),
            summary: format!("Remote Firecracker backend state: {}", self.state().await?),
            artifacts: Vec::new(),
        })
    }

    async fn port_addr(&self, guest_port: u16) -> BackendResult<Option<SocketAddr>> {
        if self.state().await? == SandboxState::Running {
            Ok(Some(SocketAddr::new(
                self.remote_config.guest_agent_addr.ip(),
                guest_port,
            )))
        } else {
            Ok(None)
        }
    }

    fn ssh_username(&self) -> &str {
        &self.remote_config.ssh_username
    }

    fn ssh_home_dir(&self) -> &str {
        &self.remote_config.ssh_home_dir
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[tokio::test]
    async fn boot_requires_prepare_without_changing_state() {
        let adapter = RemoteFirecrackerAdapter::new();

        let error = adapter.boot().await.unwrap_err();

        assert!(matches!(
            error,
            pico_core::BackendError::InvalidState {
                operation: pico_core::BackendOperation::Boot,
                actual: SandboxState::Pending,
                ..
            }
        ));
        assert_eq!(adapter.state().await.unwrap(), SandboxState::Pending);
    }

    async fn adapter_with_guest_agent() -> RemoteFirecrackerAdapter {
        let addr = guest_agent::spawn_mock_guest_agent();

        RemoteFirecrackerAdapter::with_config(RemoteFirecrackerConfig {
            guest_agent_addr: addr,
            ssh_username: "root".into(),
            ssh_home_dir: "/root".into(),
        })
    }

    fn sandbox_config() -> SandboxConfig {
        SandboxConfig {
            id: "sbx_remote_firecracker".into(),
            memory_limit_bytes: 512 * 1024 * 1024,
            network_isolated: true,
            ..Default::default()
        }
    }

    fn exec_req(command: &str, args: &[&str]) -> ExecRequest {
        ExecRequest {
            command: command.into(),
            args: args.iter().map(|arg| (*arg).into()).collect(),
            env: None,
            working_dir: None,
            timeout_secs: None,
        }
    }

    #[test]
    fn metadata_omits_suspend_and_resume() {
        // The remote adapter has no VMM control channel, so it must not
        // claim suspend/resume. Callers gate on these capabilities before
        // assuming the guest stopped executing.
        let metadata = RemoteFirecrackerAdapter::new().metadata();

        assert!(!metadata.capabilities.contains(BackendCapability::Suspend));
        assert!(!metadata.capabilities.contains(BackendCapability::Resume));
    }

    #[tokio::test]
    async fn suspend_and_resume_return_unsupported() {
        let adapter = RemoteFirecrackerAdapter::new();

        let suspend_err = adapter.suspend().await.unwrap_err();
        assert!(matches!(
            suspend_err,
            pico_core::BackendError::Unsupported { .. }
        ));

        let resume_err = adapter.resume().await.unwrap_err();
        assert!(matches!(
            resume_err,
            pico_core::BackendError::Unsupported { .. }
        ));
    }

    #[tokio::test]
    async fn attach_transport_fails_closed() {
        // RemoteFirecracker is rejected for production; attach fails closed.
        let adapter = adapter_with_guest_agent().await;

        adapter.prepare(&sandbox_config()).await.unwrap();
        adapter.boot().await.unwrap();
        let err = adapter.attach_transport().await.unwrap_err();

        assert!(matches!(err, pico_core::BackendError::Unsupported { .. }));
    }

    #[tokio::test]
    async fn wait_ready_fails_closed() {
        let adapter = adapter_with_guest_agent().await;
        adapter.prepare(&sandbox_config()).await.unwrap();
        adapter.boot().await.unwrap();

        let transport = pico_core::GuestTransport::Unix {
            path: "/tmp/pico-remote-rejected.sock".into(),
        };
        let err = adapter.wait_ready(&transport).await.unwrap_err();
        assert!(matches!(err, pico_core::BackendError::NotReady { .. }));
    }

    #[tokio::test]
    async fn exec_returns_real_command_output() {
        let adapter = adapter_with_guest_agent().await;
        adapter.prepare(&sandbox_config()).await.unwrap();
        adapter.boot().await.unwrap();
        // Attach is rejected, but direct exec via the test-only mock guest
        // agent still works for unit coverage of the exec path. Production
        // never uses this path.
        let resp = adapter
            .exec(exec_req("printf", &["pico-remote-firecracker"]))
            .await
            .unwrap();

        assert_eq!(resp.exit_code, 0);
        assert_eq!(resp.stdout, "pico-remote-firecracker");
        assert_eq!(resp.stderr, "");
    }

    /// Regression test: when an exec fails because the guest dropped the
    /// connection mid-request, the poisoned session must not be reused.
    /// The next exec must re-handshake on a fresh connection and succeed.
    #[tokio::test]
    async fn exec_error_drops_session_and_next_exec_rehandshakes() {
        let addr = guest_agent::spawn_mock_guest_agent_drop_first_exec();
        let adapter = RemoteFirecrackerAdapter::with_config(RemoteFirecrackerConfig {
            guest_agent_addr: addr,
            ssh_username: "root".into(),
            ssh_home_dir: "/root".into(),
        });
        adapter.prepare(&sandbox_config()).await.unwrap();
        adapter.boot().await.unwrap();

        let first = adapter.exec(exec_req("printf", &["first"])).await;
        assert!(first.is_err(), "dropped connection must surface an error");

        let resp = adapter.exec(exec_req("printf", &["second"])).await.unwrap();
        assert_eq!(resp.exit_code, 0);
        assert_eq!(resp.stdout, "second");
    }

    #[tokio::test]
    async fn port_addr_uses_requested_guest_port() {
        let adapter = RemoteFirecrackerAdapter::with_config(RemoteFirecrackerConfig {
            guest_agent_addr: "192.168.64.4:9999".parse().unwrap(),
            ssh_username: "odysseus".into(),
            ssh_home_dir: "/home/odysseus".into(),
        });
        *adapter.state.lock().await = SandboxState::Running;

        assert_eq!(
            adapter.port_addr(22).await.unwrap(),
            Some("192.168.64.4:22".parse().unwrap())
        );
        assert_eq!(adapter.ssh_username(), "odysseus");
        assert_eq!(adapter.ssh_home_dir(), "/home/odysseus");
    }

    #[tokio::test]
    async fn stopped_adapter_has_no_port_addr() {
        let adapter = RemoteFirecrackerAdapter::with_config(RemoteFirecrackerConfig {
            guest_agent_addr: "192.168.64.4:9999".parse().unwrap(),
            ssh_username: "odysseus".into(),
            ssh_home_dir: "/home/odysseus".into(),
        });

        adapter.prepare(&sandbox_config()).await.unwrap();
        adapter.destroy().await.unwrap();

        assert_eq!(adapter.port_addr(22).await.unwrap(), None);
    }
}

//! Configurable runtime backend test double.
//!
//! This module is gated behind `#[cfg(any(test, feature = "mock-backend"))]`
//! so it is always available in tests and can be enabled for downstream usage
//! via the `mock-backend` feature.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::Mutex;

use crate::{
    BackendCapabilities, BackendCapability, BackendError, BackendHealth, BackendMetadata,
    BackendOperation, BackendResult, BackendStats, CleanupReport, DiagnosticBundle, ExecRequest,
    ExecResponse, ForkResult, GuestTransport, NonReadyReason, PreparedSandbox, ResourceReceipt,
    RuntimeBackend, RuntimeType, SandboxConfig, SandboxState,
};

/// Failure behavior injected into one mock backend operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MockFailure {
    /// Delays one operation without changing its result.
    Delay {
        /// Operation that should be delayed.
        operation: BackendOperation,
        /// Time spent before the operation continues.
        duration: Duration,
    },
    /// Simulates an operation deadline.
    Timeout {
        /// Operation that should fail.
        operation: BackendOperation,
    },
    /// Simulates resources created before setup stopped.
    IncompleteSetup {
        /// Prepare or boot operation that should fail.
        operation: BackendOperation,
    },
    /// Simulates resources that remain after destroy or cleanup.
    PartialCleanup {
        /// Resource names that still require cleanup.
        remaining: Vec<String>,
    },
    /// Simulates an observation rejected as stale.
    StaleState {
        /// Operation that should fail.
        operation: BackendOperation,
    },
    /// Simulates a typed non-ready outcome.
    NotReady {
        /// Operation that should fail.
        operation: BackendOperation,
        /// Stable boot failure classification.
        reason: NonReadyReason,
    },
}

/// Configuration for a [`MockBackend`].
#[derive(Debug, Clone)]
pub struct MockBackendConfig {
    /// Runtime identity exposed by metadata.
    pub runtime: RuntimeType,
    /// Capabilities exposed by metadata.
    pub capabilities: BackendCapabilities,
    /// Optional failure injected into the matching operation.
    pub failure: Option<MockFailure>,
    /// Unix socket path returned by [`RuntimeBackend::attach_transport`].
    ///
    /// Defaults to a test socket path. Production transports are vsock
    /// and Unix only.
    pub guest_transport_path: String,
}

impl Default for MockBackendConfig {
    fn default() -> Self {
        Self {
            runtime: RuntimeType::Firecracker,
            capabilities: BackendCapabilities::from([
                BackendCapability::Boot,
                BackendCapability::GuestTransport,
                BackendCapability::GuestReadiness,
                BackendCapability::Exec,
                BackendCapability::Suspend,
                BackendCapability::Resume,
                BackendCapability::Fork,
                BackendCapability::Stats,
                BackendCapability::Health,
                BackendCapability::Diagnostics,
            ]),
            failure: None,
            guest_transport_path: "/tmp/pico-mock-guest.sock".into(),
        }
    }
}

/// Stateful backend test double with an operation log.
#[derive(Debug, Clone)]
pub struct MockBackend {
    config: MockBackendConfig,
    state: Arc<Mutex<SandboxState>>,
    sandbox: Arc<Mutex<Option<SandboxConfig>>>,
    operations: Arc<Mutex<Vec<BackendOperation>>>,
}

impl Default for MockBackend {
    fn default() -> Self {
        Self::new(MockBackendConfig::default())
    }
}

impl MockBackend {
    /// Creates a mock backend with the supplied behavior.
    #[must_use]
    pub fn new(config: MockBackendConfig) -> Self {
        Self {
            config,
            state: Arc::new(Mutex::new(SandboxState::Pending)),
            sandbox: Arc::new(Mutex::new(None)),
            operations: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Returns the ordered operations observed by the mock.
    pub async fn operations(&self) -> Vec<BackendOperation> {
        self.operations.lock().await.clone()
    }

    async fn begin(&self, operation: BackendOperation) -> BackendResult<()> {
        self.operations.lock().await.push(operation);
        match self.config.failure.as_ref() {
            Some(MockFailure::Delay {
                operation: delayed_operation,
                duration,
            }) if *delayed_operation == operation => {
                tokio::time::sleep(*duration).await;
                Ok(())
            }
            Some(MockFailure::Timeout {
                operation: failed_operation,
            }) if *failed_operation == operation => Err(BackendError::Timeout {
                operation,
                message: "mock deadline elapsed".into(),
            }),
            Some(MockFailure::IncompleteSetup {
                operation: failed_operation,
            }) if *failed_operation == operation => Err(BackendError::IncompleteSetup {
                operation,
                message: "mock setup stopped after creating resources".into(),
            }),
            Some(MockFailure::PartialCleanup { remaining })
                if matches!(
                    operation,
                    BackendOperation::Destroy | BackendOperation::Cleanup
                ) =>
            {
                Err(BackendError::PartialCleanup {
                    remaining: remaining.clone(),
                })
            }
            Some(MockFailure::StaleState {
                operation: failed_operation,
            }) if *failed_operation == operation => Err(BackendError::StaleState {
                message: "mock observation has an older fencing token".into(),
            }),
            Some(MockFailure::NotReady {
                operation: failed_operation,
                reason,
            }) if *failed_operation == operation => Err(BackendError::NotReady {
                operation,
                reason: *reason,
                message: "mock readiness failure".into(),
            }),
            _ => Ok(()),
        }
    }

    async fn require_state(
        &self,
        operation: BackendOperation,
        expected: &[SandboxState],
    ) -> BackendResult<()> {
        let actual = *self.state.lock().await;
        if expected.contains(&actual) {
            Ok(())
        } else {
            Err(BackendError::InvalidState {
                operation,
                expected: expected.to_vec(),
                actual,
            })
        }
    }
}

#[async_trait]
impl RuntimeBackend for MockBackend {
    fn metadata(&self) -> BackendMetadata {
        BackendMetadata {
            runtime: self.config.runtime,
            version: "mock-1".into(),
            capabilities: self.config.capabilities.clone(),
        }
    }

    async fn prepare(&self, config: &SandboxConfig) -> BackendResult<PreparedSandbox> {
        self.begin(BackendOperation::Prepare).await?;
        self.require_state(
            BackendOperation::Prepare,
            &[SandboxState::Pending, SandboxState::Preparing],
        )
        .await?;
        *self.sandbox.lock().await = Some(config.clone());
        *self.state.lock().await = SandboxState::Preparing;
        Ok(PreparedSandbox {
            resources: vec![ResourceReceipt {
                class: "mock-runtime".into(),
                name: format!("mock-{}", config.id),
                external_id: Some(config.id.clone()),
            }],
        })
    }

    async fn boot(&self) -> BackendResult<()> {
        self.begin(BackendOperation::Boot).await?;
        self.require_state(BackendOperation::Boot, &[SandboxState::Preparing])
            .await?;
        *self.state.lock().await = SandboxState::Booting;
        Ok(())
    }

    async fn attach_transport(&self) -> BackendResult<GuestTransport> {
        self.begin(BackendOperation::AttachTransport).await?;
        self.require_state(
            BackendOperation::AttachTransport,
            &[SandboxState::Booting, SandboxState::Running],
        )
        .await?;
        // Guest readiness is owned by sandboxd handshake; mock marks Running once
        // transport is attached so later backend ops remain valid without wait_ready.
        *self.state.lock().await = SandboxState::Running;
        Ok(GuestTransport::Unix {
            path: self.config.guest_transport_path.clone(),
        })
    }

    async fn wait_ready(&self, _: &GuestTransport) -> BackendResult<()> {
        self.begin(BackendOperation::WaitReady).await?;
        self.require_state(
            BackendOperation::WaitReady,
            &[SandboxState::Booting, SandboxState::Running],
        )
        .await?;
        *self.state.lock().await = SandboxState::Running;
        Ok(())
    }

    async fn exec(&self, request: ExecRequest) -> BackendResult<ExecResponse> {
        self.begin(BackendOperation::Exec).await?;
        self.require_state(BackendOperation::Exec, &[SandboxState::Running])
            .await?;
        Ok(ExecResponse {
            exit_code: 0,
            stdout: request.command,
            stderr: String::new(),
            duration_ms: 0,
        })
    }

    async fn suspend(&self) -> BackendResult<()> {
        self.begin(BackendOperation::Suspend).await?;
        self.require_state(BackendOperation::Suspend, &[SandboxState::Running])
            .await?;
        *self.state.lock().await = SandboxState::Suspended;
        Ok(())
    }

    async fn resume(&self) -> BackendResult<()> {
        self.begin(BackendOperation::Resume).await?;
        self.require_state(BackendOperation::Resume, &[SandboxState::Suspended])
            .await?;
        *self.state.lock().await = SandboxState::Running;
        Ok(())
    }

    async fn fork(&self, target: &SandboxConfig) -> BackendResult<ForkResult> {
        self.begin(BackendOperation::Fork).await?;
        self.require_state(
            BackendOperation::Fork,
            &[SandboxState::Running, SandboxState::Suspended],
        )
        .await?;
        Ok(ForkResult {
            resources: vec![ResourceReceipt {
                class: "mock-child".into(),
                name: format!("mock-{}", target.id),
                external_id: Some(target.id.clone()),
            }],
        })
    }

    async fn destroy(&self) -> BackendResult<CleanupReport> {
        self.begin(BackendOperation::Destroy).await?;
        *self.state.lock().await = SandboxState::Destroyed;
        Ok(CleanupReport {
            released: self
                .sandbox
                .lock()
                .await
                .as_ref()
                .map(|config| vec![format!("mock-{}", config.id)])
                .unwrap_or_default(),
            remaining: Vec::new(),
        })
    }

    async fn cleanup(&self) -> BackendResult<CleanupReport> {
        self.begin(BackendOperation::Cleanup).await?;
        *self.state.lock().await = SandboxState::Destroyed;
        Ok(CleanupReport::default())
    }

    async fn state(&self) -> BackendResult<SandboxState> {
        Ok(*self.state.lock().await)
    }

    async fn stats(&self) -> BackendResult<BackendStats> {
        self.begin(BackendOperation::Stats).await?;
        Ok(BackendStats {
            memory_bytes: Some(1024),
            cpu_time_ms: Some(1),
            details: serde_json::json!({"mock": true}),
        })
    }

    async fn health(&self) -> BackendResult<BackendHealth> {
        self.begin(BackendOperation::Health).await?;
        Ok(BackendHealth::ready())
    }

    async fn diagnostics(&self) -> BackendResult<DiagnosticBundle> {
        self.begin(BackendOperation::Diagnostics).await?;
        Ok(DiagnosticBundle {
            captured_at: crate::now_iso(),
            summary: "mock diagnostics".into(),
            artifacts: vec!["mock.log".into()],
        })
    }

    async fn port_addr(&self, guest_port: u16) -> BackendResult<Option<SocketAddr>> {
        Ok(Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            guest_port,
        )))
    }
}

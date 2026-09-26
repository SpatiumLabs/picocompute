//! Re-exports of [`MockBackend`] from `pico-core` for backward compatibility.

pub use pico_core::mock::{MockBackend, MockBackendConfig, MockFailure};

// Re-exports from `crate::conformance` for backward compatibility.
pub use crate::conformance::{ConformanceProfile, run_backend_conformance};

/// Successful conformance operations in execution order.
///
/// This type is retained for backward compatibility. New code should use
/// [`crate::conformance::ConformanceReport`] for structured reporting.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConformanceReport {
    /// Operations completed by the backend.
    pub completed: Vec<pico_core::BackendOperation>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use pico_core::runtime::RuntimeBackend;
    use pico_core::{BackendError, BackendOperation, ExecRequest, SandboxConfig, SandboxState};

    fn profile() -> ConformanceProfile {
        ConformanceProfile {
            sandbox: SandboxConfig {
                id: "sbx_mock".into(),
                memory_limit_bytes: 512 * 1024 * 1024,
                network_isolated: true,
                ..Default::default()
            },
            exec: ExecRequest {
                command: "true".into(),
                args: Vec::new(),
                env: None,
                working_dir: None,
                timeout_secs: Some(1),
            },
            fork_child: None,
        }
    }

    fn backend_with_failure(failure: MockFailure) -> MockBackend {
        MockBackend::new(MockBackendConfig {
            failure: Some(failure),
            ..MockBackendConfig::default()
        })
    }

    #[tokio::test]
    async fn conformance_harness_runs_full_mock_lifecycle() {
        let backend = MockBackend::default();

        let ops = run_backend_conformance(&backend, &profile()).await.unwrap();

        assert_eq!(ops.last(), Some(&BackendOperation::Cleanup));
        assert_eq!(backend.state().await.unwrap(), SandboxState::Destroyed);
    }

    #[tokio::test]
    async fn mock_simulates_timeout() {
        let backend = backend_with_failure(MockFailure::Timeout {
            operation: BackendOperation::Boot,
        });

        let error = run_backend_conformance(&backend, &profile())
            .await
            .unwrap_err();

        assert!(matches!(error, BackendError::Timeout { .. }));
    }

    #[tokio::test]
    async fn mock_simulates_incomplete_setup() {
        let backend = backend_with_failure(MockFailure::IncompleteSetup {
            operation: BackendOperation::Prepare,
        });

        let error = backend.prepare(&profile().sandbox).await.unwrap_err();

        assert!(matches!(error, BackendError::IncompleteSetup { .. }));
    }

    #[tokio::test]
    async fn mock_simulates_partial_cleanup() {
        let backend = backend_with_failure(MockFailure::PartialCleanup {
            remaining: vec!["mock-tap".into()],
        });

        let error = backend.destroy().await.unwrap_err();

        assert_eq!(
            error,
            BackendError::PartialCleanup {
                remaining: vec!["mock-tap".into()]
            }
        );
    }

    #[tokio::test]
    async fn mock_simulates_stale_state() {
        let backend = backend_with_failure(MockFailure::StaleState {
            operation: BackendOperation::Health,
        });

        let error = backend.health().await.unwrap_err();

        assert!(matches!(error, BackendError::StaleState { .. }));
    }
}

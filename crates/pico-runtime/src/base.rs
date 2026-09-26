//! Shared backend base providing state, stats, health, and lifecycle helpers.
//!
//! Every production backend wraps `VmBackendBase` for the config/state/boot-latency
//! trio that was previously copy-pasted across adapters. The base struct provides
//! canned implementations of `state()`, `stats()`, `health()`, and partial cleanup
//! logic so that backends focus on their VMM-specific mechanics.

use std::sync::Arc;

use serde_json::Value;
use tokio::sync::Mutex;

use pico_core::runtime::{
    BackendError, BackendHealth, BackendHealthStatus, BackendResult, BackendStats, CleanupReport,
};
use pico_core::{SandboxConfig, SandboxState};

/// Host-side runtime hardening configuration shared by QEMU and gVisor backends.
///
/// This replaces the previously duplicated `QemuHardening` and `GVisorHardening`
/// structs. Firecracker uses `JailerHardening` (more fields).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RuntimeHardening {
    pub isolate_namespaces: bool,
    pub unshare_mount_namespace: bool,
}

impl Default for RuntimeHardening {
    fn default() -> Self {
        Self {
            isolate_namespaces: true,
            unshare_mount_namespace: true,
        }
    }
}

impl RuntimeHardening {
    #[must_use]
    pub fn production_defaults() -> Self {
        Self {
            isolate_namespaces: true,
            unshare_mount_namespace: true,
        }
    }

    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.isolate_namespaces
    }
}

/// Shared backend state: config, lifecycle state, boot latency.
///
/// Backends wrap this struct and delegate `state()`, `stats()`, and `health()`
/// to the base. They add VMM-specific fields (child process handle, sockets,
/// backend-specific config) on top.
pub struct VmBackendBase {
    pub config: Arc<Mutex<Option<SandboxConfig>>>,
    pub state: Arc<Mutex<SandboxState>>,
    pub boot_latency_ms: Arc<Mutex<Option<u64>>>,
}

impl VmBackendBase {
    /// Creates a base with `Pending` state and unset boot latency.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: Arc::new(Mutex::new(None)),
            state: Arc::new(Mutex::new(SandboxState::Pending)),
            boot_latency_ms: Arc::new(Mutex::new(None)),
        }
    }

    /// Returns the sandbox id from the stored config, or a placeholder.
    pub async fn sandbox_id(&self) -> String {
        self.config
            .lock()
            .await
            .as_ref()
            .map(|c| c.id.clone())
            .unwrap_or_else(|| "unprepared".into())
    }

    /// Returns the currently observed lifecycle state.
    pub async fn current_state(&self) -> BackendResult<SandboxState> {
        Ok(*self.state.lock().await)
    }

    /// Sets the stored boot latency (called after a successful boot).
    pub async fn set_boot_latency_ms(&self, latency: u64) {
        *self.boot_latency_ms.lock().await = Some(latency);
    }

    /// Returns a standard `BackendStats` with state and boot latency.
    ///
    /// `backend_name` and `extra` are appended to the details JSON.
    pub async fn build_stats(
        &self,
        backend_name: &str,
        extra: Option<(&str, Value)>,
    ) -> BackendResult<BackendStats> {
        let state = self.current_state().await?;
        let boot_latency_ms = *self.boot_latency_ms.lock().await;
        let mut details = serde_json::json!({
            "state": state.as_str(),
            "boot_latency_ms": boot_latency_ms,
            "backend": backend_name,
        });
        if let Some((key, val)) = extra {
            details
                .as_object_mut()
                .expect("details must be an object")
                .insert(key.to_string(), val);
        }
        Ok(BackendStats {
            details,
            ..BackendStats::default()
        })
    }

    /// Returns a standard `BackendHealth` based on the current state.
    ///
    /// `display_name` goes into the health message (e.g., "Firecracker VM").
    pub async fn build_health(&self, display_name: &str) -> BackendResult<BackendHealth> {
        let state = self.current_state().await?;
        let (status, message) = match state {
            SandboxState::Running => (
                BackendHealthStatus::Ready,
                format!("{display_name} running"),
            ),
            SandboxState::Failed => (
                BackendHealthStatus::Degraded,
                format!("{display_name} failed"),
            ),
            SandboxState::Destroyed => (
                BackendHealthStatus::Unavailable,
                format!("{display_name} destroyed"),
            ),
            SandboxState::Suspended => (
                BackendHealthStatus::Ready,
                format!("{display_name} suspended"),
            ),
            _ => (
                BackendHealthStatus::Ready,
                format!("{display_name} in transition ({state})"),
            ),
        };
        Ok(BackendHealth {
            status,
            checked_at: pico_core::now_iso(),
            message: Some(message),
        })
    }

    /// Returns a standard `DiagnosticBundle` summary line.
    ///
    /// Callers add backend-specific artifacts after calling this.
    pub async fn build_diagnostics_summary(&self, display_name: &str) -> BackendResult<String> {
        let sandbox_id = self.sandbox_id().await;
        let state = self.current_state().await?;
        let boot_latency_ms = *self.boot_latency_ms.lock().await;
        let mut summary = format!("{display_name} backend state: {state}");
        if let Some(latency) = boot_latency_ms {
            summary.push_str(&format!(", boot_latency_ms={latency}"));
        }
        let _ = sandbox_id;
        Ok(summary)
    }

    /// Enters the destroy idempotency guard.
    ///
    /// Returns `Some(cleanup_report)` if already destroyed/destroying,
    /// or `None` if the caller should proceed with destruction.
    pub async fn begin_destroy(&self) -> Option<CleanupReport> {
        let mut state = self.state.lock().await;
        match *state {
            SandboxState::Destroyed | SandboxState::Destroying => {
                return Some(CleanupReport::default());
            }
            _ => *state = SandboxState::Destroying,
        }
        None
    }

    /// Finalises destruction: sets `Destroyed` or returns `PartialCleanup`.
    pub async fn finish_destroy(&self, remaining: Vec<String>) -> BackendResult<CleanupReport> {
        let mut state = self.state.lock().await;
        if remaining.is_empty() {
            *state = SandboxState::Destroyed;
            Ok(CleanupReport::default())
        } else {
            *state = SandboxState::Failed;
            Err(BackendError::PartialCleanup { remaining })
        }
    }
}

impl Default for VmBackendBase {
    fn default() -> Self {
        Self::new()
    }
}

/// Appends the guest-visible sandbox identity to a kernel command line.
///
/// The guest agent reads `pico_sandbox_id=` from `/proc/cmdline` to derive
/// the handshake shared secret. The id is interpolated into hypervisor-owned
/// boot arguments, so it must be a single token: reject empty ids and ids
/// containing ASCII whitespace or control characters fail-closed instead of
/// smuggling extra kernel parameters (e.g. `init=`) into the guest command
/// line.
pub(crate) fn append_sandbox_id_param(base: &str, sandbox_id: &str) -> Result<String, String> {
    if sandbox_id.is_empty() {
        return Err("sandbox id must not be empty".to_string());
    }
    if sandbox_id
        .chars()
        .any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(format!(
            "sandbox id must be a single token without whitespace (got {sandbox_id:?})"
        ));
    }
    Ok(format!("{base} pico_sandbox_id={sandbox_id}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_id_param_appends_token() {
        let cmdline = append_sandbox_id_param("console=ttyS0 root=/dev/vda", "sbx-live-test")
            .expect("valid id must be accepted");
        assert_eq!(
            cmdline,
            "console=ttyS0 root=/dev/vda pico_sandbox_id=sbx-live-test"
        );
    }

    #[test]
    fn sandbox_id_param_rejects_injection() {
        for hostile in [
            "",
            "sbx_x init=/bin/sh",
            "sbx_x\tsingle",
            "sbx_x\nrw",
            "sbx_x\0console=",
        ] {
            assert!(
                append_sandbox_id_param("console=ttyS0", hostile).is_err(),
                "hostile id must be rejected: {hostile:?}"
            );
        }
    }
}

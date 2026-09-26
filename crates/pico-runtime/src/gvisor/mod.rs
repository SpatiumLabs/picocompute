//! gVisor-backed implementation of the runtime adapter trait.
//!
//! gVisor provides a userspace application kernel that intercepts syscalls
//! and implements them in a sandboxed userspace process. This offers higher
//! density and faster startup than microVM backends, at the cost of a
//! syscall-mediated boundary rather than a hardware VM boundary.
//!
//! # Threat model
//!
//! gVisor does not provide a hardware VM boundary. Workloads running under
//! gVisor share a host kernel attack surface through the sentry process.
//! The backend selection policy must require explicit opt-in for public
//! or untrusted workloads; see [`pico_core::backend_selection`].
//!
//! # Compatibility limitations
//!
//! gVisor implements ~200 of ~300+ Linux syscalls. Common limitations:
//! - No `perf_event_open`, `fanotify`, or `kcmp`
//! - Synthetic `/proc` and `/sys` filesystems
//! - No kernel module loading
//! - No nested virtualization (`/dev/kvm`)
//! - Limited `ptrace` and `cgroups` support inside the sandbox
//!
//! Compatible: most CLI tools, package managers, language runtimes,
//! and statically-linked binaries. Incompatible: workloads that require
//! kernel modules, raw device access, or unsupported syscalls.

pub mod config;

use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Stdio;

use async_trait::async_trait;
use tokio::process::Command;

use pico_core::runtime::{
    BackendCapabilities, BackendCapability, BackendError, BackendHealth, BackendHealthStatus,
    BackendMetadata, BackendOperation, BackendResult, BackendStats, CleanupReport,
    DiagnosticBundle, GuestTransport, PreparedSandbox, ResourceReceipt, RuntimeBackend,
};
use pico_core::{ExecRequest, ExecResponse, SandboxConfig, SandboxState};

use crate::base::VmBackendBase;
use crate::gvisor::config::GVisorConfig;

pub struct GVisorAdapter {
    base: VmBackendBase,
    gvisor_config: GVisorConfig,
}

impl Default for GVisorAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl GVisorAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: VmBackendBase::new(),
            gvisor_config: GVisorConfig::detect_defaults(),
        }
    }

    #[must_use]
    pub fn with_config(gvisor_config: GVisorConfig) -> Self {
        Self {
            base: VmBackendBase::new(),
            gvisor_config,
        }
    }

    fn bundle_path(&self, sandbox_id: &str) -> PathBuf {
        self.gvisor_config.bundle_path(sandbox_id)
    }

    fn config_json_path(&self, sandbox_id: &str) -> PathBuf {
        self.gvisor_config.config_json_path(sandbox_id)
    }

    async fn sandbox_id(&self) -> Option<String> {
        self.base.config.lock().await.as_ref().map(|c| c.id.clone())
    }

    async fn runsc_output(
        &self,
        sandbox_id: &str,
        command: &str,
        args: &[&str],
        operation: BackendOperation,
    ) -> BackendResult<std::process::Output> {
        Command::new(&self.gvisor_config.runsc_binary_path)
            .arg("--root")
            .arg(&self.gvisor_config.runsc_root)
            .arg(command)
            .arg(sandbox_id)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|err| BackendError::Failed {
                operation,
                message: format!(
                    "runsc {command} {}: {err}",
                    self.gvisor_config.runsc_binary_path.display()
                ),
            })
    }

    async fn runsc_run_quiet(
        &self,
        sandbox_id: &str,
        command: &str,
        args: &[&str],
        operation: BackendOperation,
    ) -> BackendResult<()> {
        let output = self
            .runsc_output(sandbox_id, command, args, operation)
            .await?;
        if output.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(BackendError::Failed {
            operation,
            message: format!(
                "runsc {command} {} failed (exit {:?}): {}",
                sandbox_id,
                output.status.code(),
                stderr.trim()
            ),
        })
    }

    async fn create_oci_bundle(&self, sandbox_id: &str) -> BackendResult<()> {
        let bundle_path = self.bundle_path(sandbox_id);
        let config_json_path = self.config_json_path(sandbox_id);

        fs::create_dir_all(&bundle_path).map_err(|err| BackendError::Failed {
            operation: BackendOperation::Prepare,
            message: format!("create bundle directory {}: {err}", bundle_path.display()),
        })?;

        let cfg = self.base.config.lock().await;
        let sandbox_config = cfg.as_ref().ok_or_else(|| BackendError::Failed {
            operation: BackendOperation::Prepare,
            message: "sandbox config not available for bundle creation".into(),
        })?;

        let oci_config = serde_json::json!({
            "ociVersion": "1.0.2",
            "process": {
                "terminal": false,
                "user": { "uid": 0, "gid": 0 },
                "args": ["/bin/sleep", "infinity"],
                "env": [
                    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                    "PICO_SANDBOX_ID=".to_owned() + &sandbox_config.id,
                ],
                "cwd": "/",
                "capabilities": {
                    "bounding": [
                        "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FSETID",
                        "CAP_FOWNER", "CAP_MKNOD", "CAP_NET_RAW",
                        "CAP_SETGID", "CAP_SETUID", "CAP_SETFCAP",
                        "CAP_SETPCAP", "CAP_NET_BIND_SERVICE",
                        "CAP_SYS_CHROOT", "CAP_KILL", "CAP_AUDIT_WRITE"
                    ],
                    "effective": [
                        "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FSETID",
                        "CAP_FOWNER", "CAP_MKNOD", "CAP_NET_RAW",
                        "CAP_SETGID", "CAP_SETUID", "CAP_SETFCAP",
                        "CAP_SETPCAP", "CAP_NET_BIND_SERVICE",
                        "CAP_SYS_CHROOT", "CAP_KILL", "CAP_AUDIT_WRITE"
                    ],
                    "inheritable": [],
                    "permitted": [
                        "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FSETID",
                        "CAP_FOWNER", "CAP_MKNOD", "CAP_NET_RAW",
                        "CAP_SETGID", "CAP_SETUID", "CAP_SETFCAP",
                        "CAP_SETPCAP", "CAP_NET_BIND_SERVICE",
                        "CAP_SYS_CHROOT", "CAP_KILL", "CAP_AUDIT_WRITE"
                    ]
                },
                "rlimits": [
                    { "type": "RLIMIT_NOFILE", "hard": 1024, "soft": 1024 }
                ],
                "noNewPrivileges": true
            },
            "root": {
                "path": self.gvisor_config.guest_rootfs_path.display().to_string(),
                "readonly": false
            },
            "hostname": sandbox_config.id,
            "mounts": [
                {
                    "destination": "/proc",
                    "type": "proc",
                    "source": "proc",
                    "options": ["nosuid", "noexec", "nodev"]
                },
                {
                    "destination": "/dev",
                    "type": "tmpfs",
                    "source": "tmpfs",
                    "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]
                },
                {
                    "destination": "/sys",
                    "type": "sysfs",
                    "source": "sysfs",
                    "options": ["nosuid", "noexec", "nodev", "ro"]
                }
            ],
            "linux": {
                "namespaces": [
                    { "type": "pid" },
                    { "type": "network" },
                    { "type": "ipc" },
                    { "type": "uts" },
                    { "type": "mount" }
                ],
                "resources": {
                    "memory": {
                        "limit": sandbox_config.memory_limit_bytes as i64
                    },
                    "cpu": {
                        "shares": sandbox_config.cpu_shares
                    }
                },
                "seccomp": null,
                "maskedPaths": [
                    "/proc/kcore", "/proc/latency_stats",
                    "/proc/timer_list", "/proc/timer_stats",
                    "/proc/sched_debug", "/sys/firmware",
                    "/proc/scsi"
                ],
                "readonlyPaths": [
                    "/proc/asound", "/proc/bus", "/proc/fs",
                    "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"
                ]
            }
        });

        let config_json =
            serde_json::to_string_pretty(&oci_config).map_err(|err| BackendError::Failed {
                operation: BackendOperation::Prepare,
                message: format!("serialize OCI config for {}: {err}", sandbox_id),
            })?;

        fs::write(&config_json_path, config_json).map_err(|err| BackendError::Failed {
            operation: BackendOperation::Prepare,
            message: format!("write config.json {}: {err}", config_json_path.display()),
        })?;

        Ok(())
    }

    async fn remove_bundle(&self, sandbox_id: &str) -> Vec<String> {
        let bundle_path = self.bundle_path(sandbox_id);
        let mut remaining = Vec::new();
        if let Err(err) = fs::remove_dir_all(&bundle_path) {
            tracing::warn!(
                bundle = %bundle_path.display(),
                error = %err,
                "gVisor destroy left bundle directory behind"
            );
            remaining.push(format!("bundle: {}", bundle_path.display()));
        }
        remaining
    }
}

#[async_trait]
impl RuntimeBackend for GVisorAdapter {
    fn metadata(&self) -> BackendMetadata {
        BackendMetadata {
            runtime: pico_core::RuntimeType::GVisor,
            version: env!("CARGO_PKG_VERSION").into(),
            capabilities: BackendCapabilities::from([
                BackendCapability::Boot,
                BackendCapability::GuestTransport,
                BackendCapability::Exec,
                BackendCapability::Stats,
                BackendCapability::Health,
                BackendCapability::Diagnostics,
            ]),
        }
    }

    #[tracing::instrument(skip(self, config), fields(sandbox_id = %config.id))]
    async fn prepare(&self, config: &SandboxConfig) -> BackendResult<PreparedSandbox> {
        tracing::info!("Preparing gVisor resources for sandbox {}", config.id);

        self.gvisor_config
            .validate()
            .map_err(|msg| BackendError::Failed {
                operation: BackendOperation::Prepare,
                message: msg,
            })?;

        {
            let mut cfg = self.base.config.lock().await;
            *cfg = Some(config.clone());
        }

        self.create_oci_bundle(&config.id).await?;

        {
            let mut state = self.base.state.lock().await;
            *state = SandboxState::Preparing;
        }

        Ok(PreparedSandbox {
            resources: vec![
                ResourceReceipt {
                    class: "oci-bundle".into(),
                    name: self.bundle_path(&config.id).display().to_string(),
                    external_id: None,
                },
                ResourceReceipt {
                    class: "config-json".into(),
                    name: self.config_json_path(&config.id).display().to_string(),
                    external_id: None,
                },
            ],
        })
    }

    #[tracing::instrument(skip(self))]
    async fn boot(&self) -> BackendResult<()> {
        let boot_start = tokio::time::Instant::now();

        {
            let mut state = self.base.state.lock().await;
            if *state != SandboxState::Preparing {
                return Err(BackendError::InvalidState {
                    operation: BackendOperation::Boot,
                    expected: vec![SandboxState::Preparing],
                    actual: *state,
                });
            }
            *state = SandboxState::Booting;
        }

        let sandbox_id = self
            .base
            .config
            .lock()
            .await
            .as_ref()
            .map(|c| c.id.clone())
            .ok_or_else(|| BackendError::Failed {
                operation: BackendOperation::Boot,
                message: "sandbox must be prepared before boot".into(),
            })?;

        tracing::info!(
            "Starting gVisor sandbox {} (runsc={})",
            sandbox_id,
            self.gvisor_config.runsc_binary_path.display()
        );

        let boot_result: BackendResult<()> = async {
            apply_gvisor_hardening(&self.gvisor_config.hardening).map_err(|err| {
                BackendError::Failed {
                    operation: BackendOperation::Boot,
                    message: format!("gVisor hardening failed: {err}"),
                }
            })?;

            self.runsc_run_quiet(
                &sandbox_id,
                "create",
                &[
                    "--bundle",
                    &self.bundle_path(&sandbox_id).display().to_string(),
                ],
                BackendOperation::Boot,
            )
            .await?;

            self.runsc_run_quiet(&sandbox_id, "start", &[], BackendOperation::Boot)
                .await?;

            self.wait_for_sandbox_ready(&sandbox_id).await
        }
        .await;

        match boot_result {
            Ok(()) => {
                *self.base.boot_latency_ms.lock().await =
                    Some(boot_start.elapsed().as_millis() as u64);
                let mut state = self.base.state.lock().await;
                *state = SandboxState::Running;
                tracing::info!(
                    "gVisor sandbox {} boot complete in {}ms",
                    sandbox_id,
                    self.base.boot_latency_ms.lock().await.unwrap_or(0)
                );
                Ok(())
            }
            Err(err) => {
                let _message = err.to_string();
                let _ = self
                    .runsc_run_quiet(&sandbox_id, "delete", &["--force"], BackendOperation::Boot)
                    .await;
                let mut state = self.base.state.lock().await;
                *state = SandboxState::Failed;
                *self.base.boot_latency_ms.lock().await =
                    Some(boot_start.elapsed().as_millis() as u64);
                Err(err)
            }
        }
    }

    async fn attach_transport(&self) -> BackendResult<GuestTransport> {
        let state = self.base.current_state().await?;
        if state != SandboxState::Running {
            return Err(BackendError::InvalidState {
                operation: BackendOperation::AttachTransport,
                expected: vec![SandboxState::Running],
                actual: state,
            });
        }
        let sandbox_id = self
            .sandbox_id()
            .await
            .ok_or_else(|| BackendError::IncompleteSetup {
                operation: BackendOperation::AttachTransport,
                message: "sandbox ID not available for transport attachment".into(),
            })?;
        Ok(GuestTransport::Unix {
            path: self
                .gvisor_config
                .runsc_root
                .join(format!("container/{sandbox_id}/sandbox.sock"))
                .display()
                .to_string(),
        })
    }

    #[tracing::instrument(skip(self, request), fields(command = %request.command))]
    async fn exec(&self, request: ExecRequest) -> BackendResult<ExecResponse> {
        tracing::info!("Exec in gVisor sandbox: {:?}", request.command);
        let state = self.base.current_state().await?;
        if state != SandboxState::Running {
            return Err(BackendError::InvalidState {
                operation: BackendOperation::Exec,
                expected: vec![SandboxState::Running],
                actual: state,
            });
        }

        let sandbox_id = self
            .base
            .config
            .lock()
            .await
            .as_ref()
            .map(|c| c.id.clone())
            .ok_or_else(|| BackendError::Failed {
                operation: BackendOperation::Exec,
                message: "sandbox ID not available for exec".into(),
            })?;

        let exec_start = tokio::time::Instant::now();

        let args: Vec<String> = std::iter::once(request.command.clone())
            .chain(request.args.iter().cloned())
            .collect();
        let args_refs: Vec<&str> = args.iter().map(String::as_str).collect();

        let mut cmd = Command::new(&self.gvisor_config.runsc_binary_path);
        cmd.arg("--root")
            .arg(&self.gvisor_config.runsc_root)
            .arg("exec");

        if let Some(ref working_dir) = request.working_dir {
            cmd.arg("--cwd").arg(working_dir);
        }

        cmd.arg(&sandbox_id).args(&args_refs);

        if let Some(ref env) = request.env {
            for (key, value) in env {
                cmd.env(key, value);
            }
        }

        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let output = cmd.output().await.map_err(|err| BackendError::Failed {
            operation: BackendOperation::Exec,
            message: format!("runsc exec for sandbox {sandbox_id}: {err}"),
        })?;

        let duration_ms = exec_start.elapsed().as_millis() as u64;
        let exit_code = output.status.code().unwrap_or(-1);
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

        Ok(ExecResponse {
            exit_code,
            stdout,
            stderr,
            duration_ms,
        })
    }

    #[tracing::instrument(skip(self))]
    async fn destroy(&self) -> BackendResult<CleanupReport> {
        if self.base.begin_destroy().await.is_some() {
            return Ok(CleanupReport::default());
        }

        let mut remaining = Vec::new();
        if let Some(sandbox_id) = self.sandbox_id().await {
            let _ = self
                .runsc_run_quiet(
                    &sandbox_id,
                    "kill",
                    &["--all", "SIGKILL"],
                    BackendOperation::Destroy,
                )
                .await;

            if self
                .runsc_run_quiet(
                    &sandbox_id,
                    "delete",
                    &["--force"],
                    BackendOperation::Destroy,
                )
                .await
                .is_err()
            {
                remaining.push(format!("runsc-container: {sandbox_id}"));
            }

            remaining.extend(self.remove_bundle(&sandbox_id).await);
        }

        self.base.finish_destroy(remaining).await
    }

    async fn cleanup(&self) -> BackendResult<CleanupReport> {
        self.destroy().await
    }

    async fn state(&self) -> BackendResult<SandboxState> {
        self.base.current_state().await
    }

    async fn stats(&self) -> BackendResult<BackendStats> {
        let sandbox_id = self.sandbox_id().await;
        let mut stats = self.base.build_stats("gvisor", None).await?;

        if let Some(ref id) = sandbox_id
            && self.base.current_state().await? == SandboxState::Running
            && let Ok(output) = self
                .runsc_output(id, "events", &["--stats"], BackendOperation::Stats)
                .await
            && !output.stdout.is_empty()
        {
            stats.details["runsc_stats"] =
                serde_json::json!(String::from_utf8_lossy(&output.stdout).to_string());
        }

        Ok(stats)
    }

    async fn health(&self) -> BackendResult<BackendHealth> {
        let state = self.base.current_state().await?;
        if state == SandboxState::Running {
            let msg = self
                .check_runsc_state()
                .await
                .map(|s| Some(format!("runsc state: {s}")))
                .unwrap_or(None);
            Ok(BackendHealth {
                status: BackendHealthStatus::Ready,
                checked_at: pico_core::now_iso(),
                message: msg,
            })
        } else if state == SandboxState::Destroying {
            Ok(BackendHealth {
                status: BackendHealthStatus::Degraded,
                checked_at: pico_core::now_iso(),
                message: Some("gVisor sandbox is being destroyed".into()),
            })
        } else {
            self.base.build_health("gVisor sandbox").await
        }
    }

    async fn diagnostics(&self) -> BackendResult<DiagnosticBundle> {
        let sandbox_id = self.base.sandbox_id().await;
        let state = self.base.current_state().await?;
        let boot_latency = *self.base.boot_latency_ms.lock().await;

        let mut summary = format!(
            "gVisor backend state: {state} (runsc={})",
            self.gvisor_config.runsc_binary_path.display()
        );
        if let Some(latency) = boot_latency {
            summary.push_str(&format!(", boot_latency_ms={latency}"));
        }

        let mut artifacts = vec![
            self.config_json_path(&sandbox_id).display().to_string(),
            self.gvisor_config
                .log_dir(&sandbox_id)
                .display()
                .to_string(),
        ];

        if let Ok(version_output) = Command::new(&self.gvisor_config.runsc_binary_path)
            .arg("--version")
            .output()
            .await
        {
            summary.push_str(&format!(
                "; runsc: {}",
                String::from_utf8_lossy(&version_output.stdout).trim()
            ));
        }

        let compat = gvisor_compatibility_report();
        artifacts.push("compatibility: ".to_string() + &compat.len().to_string() + " limitations");
        summary.push_str(&format!("; compatibility: {compat}"));

        Ok(DiagnosticBundle {
            captured_at: pico_core::now_iso(),
            summary,
            artifacts,
        })
    }

    async fn port_addr(&self, _guest_port: u16) -> BackendResult<Option<SocketAddr>> {
        Ok(None)
    }

    fn port_exposure(&self, _guest_port: u16) -> pico_core::runtime::PortExposure {
        pico_core::runtime::PortExposure::HostProxy
    }

    fn ssh_username(&self) -> &str {
        "root"
    }

    fn ssh_home_dir(&self) -> &str {
        "/root"
    }
}

impl GVisorAdapter {
    async fn wait_for_sandbox_ready(&self, sandbox_id: &str) -> BackendResult<()> {
        let deadline = tokio::time::Instant::now() + self.gvisor_config.boot_timeout;
        loop {
            match self
                .runsc_output(sandbox_id, "exec", &["true"], BackendOperation::Boot)
                .await
            {
                Ok(output) if output.status.success() => return Ok(()),
                Ok(_output) => {
                    tracing::debug!("gVisor sandbox {sandbox_id} exec probe returned non-zero");
                }
                Err(err) => {
                    tracing::debug!("gVisor sandbox {sandbox_id} exec probe failed: {err}");
                }
            }

            if tokio::time::Instant::now() >= deadline {
                return Err(BackendError::Timeout {
                    operation: BackendOperation::Boot,
                    message: format!(
                        "timed out waiting for gVisor sandbox {} to become ready",
                        sandbox_id
                    ),
                });
            }

            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    async fn check_runsc_state(&self) -> Option<String> {
        let sandbox_id = self.sandbox_id().await?;
        self.runsc_output(&sandbox_id, "state", &[], BackendOperation::Health)
            .await
            .ok()
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
    }
}

fn gvisor_compatibility_report() -> String {
    format!(
        "compatible: CLI tools, package managers, language runtimes, static binaries; \
         limitations: no {perf}, no {fanotify}, no {kcmp}, synthetic /proc and /sys, \
         no kernel modules, no /dev/kvm, limited {ptrace}",
        perf = "perf_event_open",
        fanotify = "fanotify",
        kcmp = "kcmp",
        ptrace = "ptrace"
    )
}

fn apply_gvisor_hardening(
    hardening: &crate::RuntimeHardening,
) -> std::result::Result<(), pico_core::SandboxError> {
    if !hardening.is_enabled() {
        return Ok(());
    }

    tracing::info!(
        isolate_namespaces = hardening.isolate_namespaces,
        unshare_mount = hardening.unshare_mount_namespace,
        "applying gVisor host-side runtime hardening"
    );

    if hardening.isolate_namespaces {
        pico_runtime_hardening::apply_standard_isolation(hardening.unshare_mount_namespace)
            .map_err(|err| {
                pico_core::SandboxError::Other(format!("namespace isolation failed: {err}"))
            })?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pico_core::RuntimeType;

    fn sample_sandbox_config() -> SandboxConfig {
        SandboxConfig {
            id: "sbx_gvisor_test".into(),
            memory_limit_bytes: 512 * 1024 * 1024,
            network_isolated: true,
            ..Default::default()
        }
    }

    #[expect(dead_code, reason = "test helper for future integration tests")]
    fn exec_req(command: &str, args: &[&str]) -> ExecRequest {
        ExecRequest {
            command: command.into(),
            args: args.iter().map(|arg| (*arg).into()).collect(),
            env: None,
            working_dir: None,
            timeout_secs: None,
        }
    }

    async fn adapter_with_temp_bundle() -> (GVisorAdapter, tempfile::TempDir) {
        let tmp = tempfile::TempDir::with_prefix("pico-gvisor-test").expect("create temp dir");
        let mut config = GVisorConfig::detect_defaults();
        config.bundle_dir = tmp.path().to_path_buf();
        config.validate_paths = false;
        let adapter = GVisorAdapter::with_config(config);
        (adapter, tmp)
    }

    #[test]
    fn metadata_advertises_gvisor_capabilities() {
        let adapter = GVisorAdapter::new();

        let metadata = adapter.metadata();

        assert_eq!(metadata.runtime, RuntimeType::GVisor);
        assert!(metadata.capabilities.contains(BackendCapability::Boot));
        assert!(
            metadata
                .capabilities
                .contains(BackendCapability::GuestTransport)
        );
        assert!(metadata.capabilities.contains(BackendCapability::Exec));
        assert!(metadata.capabilities.contains(BackendCapability::Stats));
        assert!(metadata.capabilities.contains(BackendCapability::Health));
        assert!(
            metadata
                .capabilities
                .contains(BackendCapability::Diagnostics)
        );
        assert!(!metadata.capabilities.contains(BackendCapability::Fork));
        assert!(!metadata.capabilities.contains(BackendCapability::Suspend));
        assert!(!metadata.capabilities.contains(BackendCapability::Resume));
        assert!(
            !metadata
                .capabilities
                .contains(BackendCapability::BackendManagedPortForwarding)
        );
    }

    #[test]
    fn metadata_advertises_version() {
        let metadata = GVisorAdapter::new().metadata();
        assert!(!metadata.version.is_empty());
    }

    #[tokio::test]
    async fn boot_requires_prepare_without_changing_state() {
        let adapter = GVisorAdapter::new();

        let error = adapter.boot().await.unwrap_err();

        assert!(matches!(
            error,
            BackendError::InvalidState {
                operation: BackendOperation::Boot,
                actual: SandboxState::Pending,
                ..
            }
        ));
        assert_eq!(adapter.state().await.unwrap(), SandboxState::Pending);
    }

    #[tokio::test]
    async fn exec_requires_running_state() {
        let adapter = GVisorAdapter::new();

        let error = adapter
            .exec(ExecRequest {
                command: "true".into(),
                args: vec![],
                env: None,
                working_dir: None,
                timeout_secs: None,
            })
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            BackendError::InvalidState {
                operation: BackendOperation::Exec,
                actual: SandboxState::Pending,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn destroy_is_idempotent() {
        let adapter = GVisorAdapter::new();

        let first = adapter.destroy().await.unwrap();
        assert!(first.released.is_empty());

        let second = adapter.destroy().await.unwrap();
        assert!(second.released.is_empty());

        assert_eq!(adapter.state().await.unwrap(), SandboxState::Destroyed);
    }

    #[tokio::test]
    async fn destroy_transitions_to_destroyed_state() {
        let adapter = GVisorAdapter::new();

        adapter.destroy().await.unwrap();

        assert_eq!(adapter.state().await.unwrap(), SandboxState::Destroyed);
    }

    #[tokio::test]
    async fn cleanup_delegates_to_destroy() {
        let adapter = GVisorAdapter::new();

        let report = adapter.cleanup().await.unwrap();

        assert_eq!(adapter.state().await.unwrap(), SandboxState::Destroyed);
        assert!(report.released.is_empty());
        assert!(report.remaining.is_empty());
    }

    #[tokio::test]
    async fn attach_transport_requires_running_state() {
        let adapter = GVisorAdapter::new();

        let error = adapter.attach_transport().await.unwrap_err();

        assert!(matches!(
            error,
            BackendError::InvalidState {
                operation: BackendOperation::AttachTransport,
                actual: SandboxState::Pending,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn fork_returns_unsupported() {
        let adapter = GVisorAdapter::new();

        let error = adapter
            .fork(&SandboxConfig {
                id: "sbx_child".into(),
                ..sample_sandbox_config()
            })
            .await
            .unwrap_err();

        assert!(matches!(error, BackendError::Unsupported { .. }));
    }

    #[test]
    fn port_exposure_returns_host_proxy() {
        let adapter = GVisorAdapter::new();

        let exposure = adapter.port_exposure(22);
        assert_eq!(exposure, pico_core::runtime::PortExposure::HostProxy);
    }

    #[test]
    fn ssh_username_returns_root() {
        let adapter = GVisorAdapter::new();
        assert_eq!(adapter.ssh_username(), "root");
    }

    #[test]
    fn ssh_home_dir_returns_root() {
        let adapter = GVisorAdapter::new();
        assert_eq!(adapter.ssh_home_dir(), "/root");
    }

    #[tokio::test]
    async fn stats_returns_state_and_boot_latency() {
        let adapter = GVisorAdapter::new();

        let stats = adapter.stats().await.unwrap();

        assert!(
            stats
                .details
                .get("state")
                .and_then(|v| v.as_str())
                .is_some_and(|s| s == "Pending")
        );
        assert!(
            stats
                .details
                .get("boot_latency_ms")
                .is_some_and(|v| v.is_null())
        );
        assert_eq!(
            stats.details.get("backend").and_then(|v| v.as_str()),
            Some("gvisor")
        );
    }

    #[tokio::test]
    async fn health_reports_degraded_when_failed() {
        let adapter = GVisorAdapter::new();
        *adapter.base.state.lock().await = SandboxState::Failed;

        let health = adapter.health().await.unwrap();

        assert_eq!(health.status, BackendHealthStatus::Degraded);
        assert!(health.message.is_some_and(|m| m.contains("failed")));
    }

    #[tokio::test]
    async fn health_reports_unavailable_when_destroyed() {
        let adapter = GVisorAdapter::new();
        *adapter.base.state.lock().await = SandboxState::Destroyed;

        let health = adapter.health().await.unwrap();

        assert_eq!(health.status, BackendHealthStatus::Unavailable);
        assert!(health.message.is_some_and(|m| m.contains("destroyed")));
    }

    #[tokio::test]
    async fn health_reports_ready_when_pending() {
        let adapter = GVisorAdapter::new();

        let health = adapter.health().await.unwrap();

        assert_eq!(health.status, BackendHealthStatus::Ready);
    }

    #[tokio::test]
    async fn diagnostics_includes_gvisor_details() {
        let adapter = GVisorAdapter::new();

        let bundle = adapter.diagnostics().await.unwrap();

        assert!(bundle.summary.contains("gVisor backend state"));
        assert!(bundle.summary.contains("runsc="));
        assert!(bundle.summary.contains("compatibility:"));
        assert!(!bundle.artifacts.is_empty());
    }

    #[tokio::test]
    async fn port_addr_returns_none_when_not_running() {
        let adapter = GVisorAdapter::new();

        let addr = adapter.port_addr(8080).await.unwrap();

        assert!(addr.is_none());
    }

    #[test]
    fn gvisor_compatibility_report_lists_known_limitations() {
        let report = gvisor_compatibility_report();
        assert!(report.contains("perf_event_open"));
        assert!(report.contains("synthetic /proc"));
        assert!(report.contains("no kernel modules"));
    }

    #[test]
    fn with_config_preserves_custom_paths() {
        let mut config = GVisorConfig::detect_defaults();
        config.runsc_root = "/tmp/runsc-test".into();
        config.bundle_dir = "/tmp/bundles".into();
        let adapter = GVisorAdapter::with_config(config);

        let metadata = adapter.metadata();
        assert_eq!(metadata.runtime, RuntimeType::GVisor);
        assert_eq!(
            adapter.base.state.blocking_lock().clone(),
            SandboxState::Pending
        );
    }

    #[tokio::test]
    async fn prepare_with_validation_disabled_sets_state() {
        let (adapter, _tmp) = adapter_with_temp_bundle().await;

        let _ = adapter.prepare(&sample_sandbox_config()).await.unwrap();

        assert_eq!(adapter.state().await.unwrap(), SandboxState::Preparing);
    }

    #[tokio::test]
    async fn conformance_capability_declarations_match_gvisor_lifecycle() {
        let (adapter, _tmp) = adapter_with_temp_bundle().await;
        let metadata = adapter.metadata();

        // gVisor declares Boot, GuestTransport, Exec, Stats, Health, Diagnostics.
        let expected = BackendCapabilities::from([
            BackendCapability::Boot,
            BackendCapability::GuestTransport,
            BackendCapability::Exec,
            BackendCapability::Stats,
            BackendCapability::Health,
            BackendCapability::Diagnostics,
        ]);
        assert_eq!(metadata.capabilities, expected);

        // gVisor does not support GuestReadiness, Suspend, Resume, Fork, or
        // BackendManagedPortForwarding. These must be explicitly absent.
        assert!(
            !metadata
                .capabilities
                .contains(BackendCapability::GuestReadiness)
        );
        assert!(!metadata.capabilities.contains(BackendCapability::Suspend));
        assert!(!metadata.capabilities.contains(BackendCapability::Resume));
        assert!(!metadata.capabilities.contains(BackendCapability::Fork));
        assert!(
            !metadata
                .capabilities
                .contains(BackendCapability::BackendManagedPortForwarding)
        );

        // Unsupported operations return Unsupported error.
        let fork_err = adapter
            .fork(&SandboxConfig {
                id: "sbx_gv_fork".into(),
                network_isolated: true,
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert!(matches!(fork_err, BackendError::Unsupported { .. }));

        let suspend_err = adapter.suspend().await.unwrap_err();
        assert!(matches!(suspend_err, BackendError::Unsupported { .. }));

        let resume_err = adapter.resume().await.unwrap_err();
        assert!(matches!(resume_err, BackendError::Unsupported { .. }));
    }

    #[test]
    fn trusted_fast_path_required_set_satisfied_by_gvisor() {
        use crate::conformance::required_capabilities_for_workload_class;
        use pico_core::WorkloadClass;

        let metadata = GVisorAdapter::new().metadata();

        // gVisor passes the trusted-fast-path profile without
        // declaring GuestReadiness. This pins the passing report at the
        // metadata level (no runsc binary needed).
        let trusted = required_capabilities_for_workload_class(WorkloadClass::TrustedFastPath);
        assert!(
            metadata.capabilities.supports_all(&trusted),
            "gVisor must satisfy trusted-fast-path required set, missing: {:?}",
            metadata.capabilities.missing(&trusted)
        );

        // The public-untrusted profile still requires GuestReadiness, which
        // gVisor correctly omits, so gVisor stays trusted-only.
        let public = required_capabilities_for_workload_class(WorkloadClass::PublicUntrusted);
        assert_eq!(
            metadata.capabilities.missing(&public),
            vec![BackendCapability::GuestReadiness]
        );
    }
}

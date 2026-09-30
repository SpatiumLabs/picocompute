//! Firecracker-backed implementation of the runtime adapter trait.

pub mod api;
pub mod config;

use std::ffi::OsString;
use std::fs::File;
use std::net::SocketAddr;
use std::path::Path;
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::process::Command;
use tokio::sync::Mutex;
use tokio::time::{Instant, sleep};

use pico_core::Result;
use pico_core::cpu_isolation::apply_cpu_affinity;
use pico_core::runtime::{
    BackendCapabilities, BackendCapability, BackendError, BackendHealth, BackendMetadata,
    BackendOperation, BackendRestoreContext, BackendResult, BackendStats, CleanupReport,
    DiagnosticBundle, ForkResult, GuestTransport, PreparedSandbox, ResourceReceipt, RuntimeBackend,
};
use pico_core::{ExecRequest, ExecResponse, SandboxConfig, SandboxError, SandboxState};
use pico_core::{
    apply_core_sched_tagging_to_pid, apply_service_class_sched_policy, is_sched_permission_denied,
    probe_core_scheduling,
};

use crate::base::VmBackendBase;

use crate::firecracker::api::FirecrackerApiClient;
use crate::firecracker::config::{Architecture, FirecrackerConfig, NetworkConfig};

pub struct FirecrackerAdapter {
    base: VmBackendBase,
    vm_process: Arc<Mutex<Option<tokio::process::Child>>>,
    firecracker_config: FirecrackerConfig,
    network: Arc<Mutex<Option<NetworkConfig>>>,
}

impl FirecrackerAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: VmBackendBase::new(),
            vm_process: Arc::new(Mutex::new(None)),
            firecracker_config: FirecrackerConfig::detect_defaults(),
            network: Arc::new(Mutex::new(None)),
        }
    }

    #[must_use]
    pub fn with_config(firecracker_config: FirecrackerConfig) -> Self {
        Self {
            base: VmBackendBase::new(),
            vm_process: Arc::new(Mutex::new(None)),
            firecracker_config,
            network: Arc::new(Mutex::new(None)),
        }
    }

    /// Guest-agent vsock port reserved by ADR-0003 for Firecracker.
    const GUEST_AGENT_VSOCK_PORT: u32 = 52;

    fn api_socket_path(&self, sandbox_id: &str) -> std::path::PathBuf {
        self.firecracker_config
            .api_socket_dir
            .join(format!("{sandbox_id}.firecracker.sock"))
    }

    fn vsock_uds_path(&self, sandbox_id: &str) -> std::path::PathBuf {
        self.firecracker_config
            .api_socket_dir
            .join(format!("{sandbox_id}.vsock"))
    }

    fn stdout_log_path(&self, sandbox_id: &str) -> std::path::PathBuf {
        self.firecracker_config
            .api_socket_dir
            .join(format!("{sandbox_id}.firecracker.stdout.log"))
    }

    fn stderr_log_path(&self, sandbox_id: &str) -> std::path::PathBuf {
        self.firecracker_config
            .api_socket_dir
            .join(format!("{sandbox_id}.firecracker.stderr.log"))
    }

    fn vmm_log_path(&self, sandbox_id: &str) -> std::path::PathBuf {
        self.firecracker_config
            .api_socket_dir
            .join(format!("{sandbox_id}.firecracker.vmm.log"))
    }

    async fn kill_vm_process(&self) -> Result<()> {
        let mut vm_proc = self.vm_process.lock().await;
        if let Some(mut child) = vm_proc.take() {
            child.kill().await?;
        }
        Ok(())
    }

    async fn vm_exit_status(&self) -> Result<Option<std::process::ExitStatus>> {
        let mut vm_proc = self.vm_process.lock().await;
        if let Some(child) = vm_proc.as_mut() {
            return child.try_wait().map_err(Into::into);
        }
        Ok(None)
    }
}

impl Default for FirecrackerAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RuntimeBackend for FirecrackerAdapter {
    fn metadata(&self) -> BackendMetadata {
        BackendMetadata {
            runtime: pico_core::RuntimeType::Firecracker,
            version: env!("CARGO_PKG_VERSION").into(),
            capabilities: BackendCapabilities::from([
                BackendCapability::Boot,
                BackendCapability::GuestTransport,
                BackendCapability::GuestReadiness,
                BackendCapability::Exec,
                BackendCapability::Suspend,
                BackendCapability::Resume,
                BackendCapability::SnapshotRestore,
                BackendCapability::Stats,
                BackendCapability::Health,
                BackendCapability::Diagnostics,
            ]),
        }
    }

    #[tracing::instrument(skip(self, config), fields(sandbox_id = %config.id))]
    async fn prepare(&self, config: &SandboxConfig) -> BackendResult<PreparedSandbox> {
        tracing::info!("Preparing Firecracker resources for sandbox {}", config.id);
        let fc_cfg = &self.firecracker_config;
        if fc_cfg.validate_paths {
            if !fc_cfg.kernel.image_path.exists() {
                return Err(BackendError::Failed {
                    operation: BackendOperation::Prepare,
                    message: format!(
                        "kernel image not found at {}",
                        fc_cfg.kernel.image_path.display()
                    ),
                });
            }
            if !fc_cfg.rootfs_path.exists() {
                return Err(BackendError::Failed {
                    operation: BackendOperation::Prepare,
                    message: format!("rootfs not found at {}", fc_cfg.rootfs_path.display()),
                });
            }
            if let Some(ref initrd) = fc_cfg.initrd_path
                && !initrd.exists()
            {
                return Err(BackendError::Failed {
                    operation: BackendOperation::Prepare,
                    message: format!("initrd not found at {}", initrd.display()),
                });
            }
        }
        {
            let mut cfg = self.base.config.lock().await;
            *cfg = Some(config.clone());
        }
        {
            let mut network = self.network.lock().await;
            *network = Some(NetworkConfig::for_sandbox_id(&config.id));
        }
        {
            let mut state = self.base.state.lock().await;
            *state = SandboxState::Preparing;
        }
        Ok(PreparedSandbox {
            resources: vec![ResourceReceipt {
                class: "api-socket".into(),
                name: self.api_socket_path(&config.id).display().to_string(),
                external_id: None,
            }],
        })
    }

    #[tracing::instrument(skip(self))]
    async fn boot(&self) -> BackendResult<()> {
        let boot_start = Instant::now();
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

        let sandbox_config =
            self.base
                .config
                .lock()
                .await
                .clone()
                .ok_or_else(|| BackendError::Failed {
                    operation: BackendOperation::Boot,
                    message: "sandbox must be prepared before boot".into(),
                })?;
        let fc_cfg = &self.firecracker_config;
        let socket_path = self.api_socket_path(&sandbox_config.id);
        let stdout_log_path = self.stdout_log_path(&sandbox_config.id);
        let stderr_log_path = self.stderr_log_path(&sandbox_config.id);
        let vmm_log_path = self.vmm_log_path(&sandbox_config.id);
        let network = self
            .network
            .lock()
            .await
            .clone()
            .ok_or_else(|| BackendError::Failed {
                operation: BackendOperation::Boot,
                message: "sandbox network must be prepared before boot".into(),
            })?;
        remove_stale_socket(&socket_path)
            .await
            .map_err(|err| BackendError::Failed {
                operation: BackendOperation::Boot,
                message: format!("failed to remove stale API socket: {err}"),
            })?;

        tracing::info!(
            "Starting Firecracker VM (sandbox={}, arch={:?}, kernel={}, socket={}, cpu_template={:?}, jailer={})",
            sandbox_config.id,
            fc_cfg.arch,
            fc_cfg.kernel.image_path.display(),
            socket_path.display(),
            fc_cfg.cpu_template,
            fc_cfg
                .jailer_binary_path
                .as_ref()
                .map_or("none", |p| p.to_str().unwrap_or("?")),
        );

        let stdout_log = File::create(&stdout_log_path).map_err(|err| BackendError::Failed {
            operation: BackendOperation::Boot,
            message: format!(
                "create Firecracker stdout log {}: {err}",
                stdout_log_path.display()
            ),
        })?;
        let stderr_log = File::create(&stderr_log_path).map_err(|err| BackendError::Failed {
            operation: BackendOperation::Boot,
            message: format!(
                "create Firecracker stderr log {}: {err}",
                stderr_log_path.display()
            ),
        })?;

        if let Some(ref jailer) = fc_cfg.jailer_binary_path {
            let mut command = Command::new(jailer);
            command.args(jailer_args(
                &fc_cfg.firecracker_binary_path,
                fc_cfg.arch,
                &socket_path,
                &sandbox_config.id,
                &fc_cfg.jailer_hardening,
            ));
            let child = command
                .stdout(Stdio::from(stdout_log))
                .stderr(Stdio::from(stderr_log))
                .spawn()
                .map_err(|err| BackendError::Failed {
                    operation: BackendOperation::Boot,
                    message: format!(
                        "failed to launch Firecracker jailer {}: {err}",
                        jailer.display()
                    ),
                })?;
            let mut vm_proc = self.vm_process.lock().await;
            *vm_proc = Some(child);
        } else {
            let mut command = Command::new(&fc_cfg.firecracker_binary_path);
            command.args(firecracker_args(fc_cfg.arch, &socket_path));
            let child = command
                .stdout(Stdio::from(stdout_log))
                .stderr(Stdio::from(stderr_log))
                .spawn()
                .map_err(|err| BackendError::Failed {
                    operation: BackendOperation::Boot,
                    message: format!(
                        "failed to launch Firecracker binary {}: {err}",
                        fc_cfg.firecracker_binary_path.display()
                    ),
                })?;
            // Keep VMM stderr. Firecracker often reports boot-source and config failures only there.
            let mut vm_proc = self.vm_process.lock().await;
            *vm_proc = Some(child);
        }

        // Apply CPU pinning if a CPU set was configured
        if let Some(ref cpu_set) = sandbox_config.cpu_set {
            let vm_proc = self.vm_process.lock().await;
            if let Some(ref child) = *vm_proc
                && let Some(pid) = child.id()
                && let Err(err) = apply_cpu_affinity(
                    pid,
                    &pico_core::cpu_isolation::CpuSet::new(cpu_set.iter().copied())
                        .unwrap_or_else(|| pico_core::cpu_isolation::CpuSet::new([0]).unwrap()),
                )
            {
                tracing::warn!(
                    sandbox_id = %sandbox_config.id,
                    pid = pid,
                    error = %err,
                    "failed to apply CPU pinning to Firecracker VMM process"
                );
            }
        }

        let start_result: Result<()> = async {
            // Apply the service-class scheduling policy to the VMM pid at
            // spawn. LS is a no-op (already SCHED_OTHER); BE applies
            // SCHED_IDLE. Permission-denied (restricted env without
            // CAP_SYS_NICE) warns and continues; any other control failure
            // fails boot closed inside this closure so the outer handler
            // kills the spawned VMM and marks Failed instead of leaking it.
            {
                let vm_proc = self.vm_process.lock().await;
                if let Some(ref child) = *vm_proc
                    && let Some(pid) = child.id()
                    && sandbox_config.service_class.is_best_effort()
                    && let Err(err) =
                        apply_service_class_sched_policy(sandbox_config.service_class, pid)
                {
                    if is_sched_permission_denied(&err) {
                        tracing::warn!(
                            sandbox_id = %sandbox_config.id,
                            pid = pid,
                            error = %err,
                            "sched policy denied for VMM process (restricted env without CAP_SYS_NICE); continuing at default priority"
                        );
                    } else {
                        return Err(SandboxError::Other(format!(
                            "sched policy failed for Firecracker VMM pid {pid}: {err}"
                        )));
                    }
                }
            }
            // Core-sched cookie tagging for BE VMM pids (gated default-off).
            // Runs after SCHED_IDLE so the S-NOISY comparison is
            // cookie-tagged vs SMT-exclusion-only. Disabled policy or an
            // Unsupported probe stays on SMT-exclusion-only without a
            // syscall; permission-denied warns and continues, other
            // failures fail boot closed.
            {
                let vm_proc = self.vm_process.lock().await;
                if let Some(ref child) = *vm_proc
                    && let Some(pid) = child.id()
                    && sandbox_config.service_class.is_best_effort()
                    && fc_cfg.core_sched_policy.enabled
                {
                    let support = probe_core_scheduling();
                    match apply_core_sched_tagging_to_pid(
                        &fc_cfg.core_sched_policy,
                        &support,
                        pid,
                    ) {
                        Ok(pico_core::CoreSchedTagOutcome::Tagged { cookie }) => {
                            tracing::info!(
                                sandbox_id = %sandbox_config.id,
                                pid = pid,
                                cookie = cookie,
                                "core-sched cookie tagged Firecracker VMM"
                            );
                        }
                        Ok(
                            pico_core::CoreSchedTagOutcome::SkippedDisabled
                            | pico_core::CoreSchedTagOutcome::SkippedUnsupported { .. },
                        ) => {}
                        Err(err) => {
                            if is_sched_permission_denied(&err) {
                                tracing::warn!(
                                    sandbox_id = %sandbox_config.id,
                                    pid = pid,
                                    error = %err,
                                    "core-sched tagging denied for VMM process; continuing SMT-exclusion-only"
                                );
                            } else {
                                return Err(SandboxError::Other(format!(
                                    "core-sched tagging failed for Firecracker VMM pid {pid}: {err}"
                                )));
                            }
                        }
                    }
                }
            }
            wait_for_socket(&socket_path, Duration::from_secs(5)).await?;

            let client = FirecrackerApiClient::new(&socket_path);
            let boot_args = kernel_cmdline(&fc_cfg.kernel.cmdline, &sandbox_config.id, &network)
                .map_err(|err| BackendError::Failed {
                    operation: BackendOperation::Boot,
                    message: format!("invalid sandbox identity for kernel cmdline: {err}"),
                })?;
            self.configure_logger_when_api_ready(&client, &vmm_log_path, Duration::from_secs(5))
                .await?;
            client
                .put_boot_source(path_to_str(&fc_cfg.kernel.image_path)?, &boot_args)
                .await?;
            client
                .put_machine_config(
                    fc_cfg.vcpu_count,
                    fc_cfg.mem_size_mib,
                    fc_cfg.cpu_template.as_deref(),
                )
                .await?;
            client
                .put_drive("rootfs", path_to_str(&fc_cfg.rootfs_path)?)
                .await?;
            let cid = fc_cfg.vsock_guest_cid.unwrap_or(3);
            let uds = self.vsock_uds_path(&sandbox_config.id);
            client.put_vsock("root", cid, path_to_str(&uds)?).await?;
            if fc_cfg.enable_rng {
                client.put_entropy().await?;
            }
            client
                .put_network_interface("eth0", &network.tap_name, &network.guest_mac)
                .await?;
            client.instance_start().await?;
            Ok(())
        }
        .await;

        if let Err(err) = start_result {
            let exit_status = self.vm_exit_status().await.ok().flatten();
            let _ = self.kill_vm_process().await;
            let err = enrich_with_firecracker_logs(
                err,
                exit_status.as_ref(),
                &vmm_log_path,
                &stdout_log_path,
                &stderr_log_path,
            );
            let _message = err.to_string();
            let mut state = self.base.state.lock().await;
            *state = SandboxState::Failed;
            *self.base.boot_latency_ms.lock().await = Some(boot_start.elapsed().as_millis() as u64);
            return Err(err.into());
        }

        {
            *self.base.boot_latency_ms.lock().await = Some(boot_start.elapsed().as_millis() as u64);
            let mut state = self.base.state.lock().await;
            *state = SandboxState::Running;
        }
        tracing::info!(
            "Firecracker VM boot complete in {}ms",
            self.base.boot_latency_ms.lock().await.unwrap_or(0)
        );
        Ok(())
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
        let sandbox_id = self.base.sandbox_id().await;
        Ok(GuestTransport::Vsock {
            cid: self.firecracker_config.vsock_guest_cid.unwrap_or(3),
            port: Self::GUEST_AGENT_VSOCK_PORT,
            uds_path: Some(self.vsock_uds_path(&sandbox_id).display().to_string()),
        })
    }

    async fn wait_ready(&self, transport: &GuestTransport) -> BackendResult<()> {
        match transport {
            GuestTransport::Vsock { .. } | GuestTransport::Unix { .. } => {
                *self.base.state.lock().await = SandboxState::Running;
                Ok(())
            }
        }
    }

    #[tracing::instrument(skip(self))]
    async fn destroy(&self) -> BackendResult<CleanupReport> {
        if self.base.begin_destroy().await.is_some() {
            return Ok(CleanupReport::default());
        }

        let _ = self.kill_vm_process().await;
        *self.network.lock().await = None;

        self.base.finish_destroy(Vec::new()).await
    }

    async fn cleanup(&self) -> BackendResult<CleanupReport> {
        self.destroy().await
    }

    #[tracing::instrument(skip(self))]
    async fn suspend(&self) -> BackendResult<()> {
        {
            let mut state = self.base.state.lock().await;
            if *state == SandboxState::Suspended {
                return Ok(());
            }
            if *state != SandboxState::Running {
                return Err(BackendError::InvalidState {
                    operation: BackendOperation::Suspend,
                    expected: vec![SandboxState::Running, SandboxState::Suspended],
                    actual: *state,
                });
            }
            *state = SandboxState::Suspending;
        }
        tracing::info!("Suspending Firecracker VM via PATCH /vm Paused");
        let pause_result = self.pause_guest_execution().await;
        match pause_result {
            Ok(()) => {
                {
                    let mut state = self.base.state.lock().await;
                    *state = SandboxState::Suspended;
                }
                Ok(())
            }
            Err(err) => {
                // The guest keeps running when pause fails, so revert to
                // Running instead of stranding the backend in Suspending.
                *self.base.state.lock().await = SandboxState::Running;
                Err(err)
            }
        }
    }

    #[tracing::instrument(skip(self))]
    async fn resume(&self) -> BackendResult<()> {
        {
            let mut state = self.base.state.lock().await;
            if *state == SandboxState::Running {
                return Ok(());
            }
            if *state != SandboxState::Suspended {
                return Err(BackendError::InvalidState {
                    operation: BackendOperation::Resume,
                    expected: vec![SandboxState::Suspended, SandboxState::Running],
                    actual: *state,
                });
            }
            *state = SandboxState::Resuming;
        }
        tracing::info!("Resuming Firecracker VM via PATCH /vm Resumed");
        let resume_result = self.resume_guest_execution().await;
        match resume_result {
            Ok(()) => {
                {
                    let mut state = self.base.state.lock().await;
                    *state = SandboxState::Running;
                }
                Ok(())
            }
            Err(err) => {
                // The guest is still paused when resume fails, so revert to
                // Suspended instead of stranding the backend in Resuming.
                *self.base.state.lock().await = SandboxState::Suspended;
                Err(err)
            }
        }
    }

    async fn restore_snapshot(&self, ctx: &BackendRestoreContext) -> BackendResult<()> {
        {
            let state = self.base.current_state().await?;
            if state != SandboxState::Running {
                return Err(BackendError::InvalidState {
                    operation: BackendOperation::RestoreSnapshot,
                    expected: vec![SandboxState::Running],
                    actual: state,
                });
            }
        }

        if ctx.blob_paths.len() != 2 {
            return Err(BackendError::Failed {
                operation: BackendOperation::RestoreSnapshot,
                message: "firecracker snapshot restore requires exactly two blob paths: [memory_dump, vm_state]".into(),
            });
        }

        let sandbox_id = {
            let config = self.base.config.lock().await;
            config
                .as_ref()
                .map(|c| c.id.clone())
                .ok_or_else(|| BackendError::Failed {
                    operation: BackendOperation::RestoreSnapshot,
                    message: "sandbox must be prepared and booted before snapshot restore".into(),
                })?
        };

        let socket_path = self.api_socket_path(&sandbox_id);
        let client = FirecrackerApiClient::new(&socket_path);

        let memory_path = ctx.blob_paths[0]
            .to_str()
            .ok_or_else(|| BackendError::Failed {
                operation: BackendOperation::RestoreSnapshot,
                message: "memory blob path is not valid UTF-8".into(),
            })?;

        let snapshot_path = ctx.blob_paths[1]
            .to_str()
            .ok_or_else(|| BackendError::Failed {
                operation: BackendOperation::RestoreSnapshot,
                message: "vm state blob path is not valid UTF-8".into(),
            })?;

        tracing::info!(
            sandbox_id = %sandbox_id,
            memory_path = %memory_path,
            snapshot_path = %snapshot_path,
            "restoring Firecracker VM from snapshot"
        );

        client
            .put_snapshot_load(snapshot_path, memory_path)
            .await
            .map_err(|err| BackendError::Failed {
                operation: BackendOperation::RestoreSnapshot,
                message: format!("firecracker snapshot load failed: {err}"),
            })?;

        tracing::info!(
            sandbox_id = %sandbox_id,
            "Firecracker VM snapshot restore complete"
        );
        Ok(())
    }

    async fn fork(&self, _target: &SandboxConfig) -> BackendResult<ForkResult> {
        Err(BackendError::Unsupported {
            capability: BackendCapability::Fork,
        })
    }

    async fn state(&self) -> BackendResult<SandboxState> {
        self.base.current_state().await
    }

    #[tracing::instrument(skip(self, req), fields(command = %req.command))]
    async fn exec(&self, req: ExecRequest) -> BackendResult<ExecResponse> {
        let _ = req;
        tracing::info!("Forwarding exec to guest-agent");
        let state = self.base.current_state().await?;
        if state != SandboxState::Running {
            return Err(BackendError::InvalidState {
                operation: BackendOperation::Exec,
                expected: vec![SandboxState::Running],
                actual: state,
            });
        }
        // Direct adapter exec is not supported: guest sessions are owned by
        // sandboxd over the attached vsock transport. Callers must go through
        // the supervisor handshake instead of dialing the guest directly.
        Err(BackendError::Failed {
            operation: BackendOperation::Exec,
            message: "direct adapter exec is not supported; use the sandboxd guest session".into(),
        })
    }

    async fn stats(&self) -> BackendResult<BackendStats> {
        self.base.build_stats("Firecracker", None).await
    }

    async fn health(&self) -> BackendResult<BackendHealth> {
        let mut health = self.base.build_health("Firecracker VM").await?;
        if matches!(self.base.current_state().await?, SandboxState::Running) {
            health.message = None;
        }
        Ok(health)
    }

    async fn diagnostics(&self) -> BackendResult<DiagnosticBundle> {
        let sandbox_id = self.base.sandbox_id().await;
        let summary = self.base.build_diagnostics_summary("Firecracker").await?;
        Ok(DiagnosticBundle {
            captured_at: pico_core::now_iso(),
            summary,
            artifacts: vec![
                self.stdout_log_path(&sandbox_id).display().to_string(),
                self.stderr_log_path(&sandbox_id).display().to_string(),
                self.vmm_log_path(&sandbox_id).display().to_string(),
            ],
        })
    }

    async fn port_addr(&self, guest_port: u16) -> BackendResult<Option<SocketAddr>> {
        let state = self.base.current_state().await?;
        if state == SandboxState::Running {
            let guest_agent_addr = self.guest_agent_addr().await;
            Ok(Some(SocketAddr::new(guest_agent_addr.ip(), guest_port)))
        } else {
            Ok(None)
        }
    }

    fn ssh_username(&self) -> &str {
        "root"
    }

    fn ssh_home_dir(&self) -> &str {
        "/root"
    }
}

impl FirecrackerAdapter {
    /// Pauses guest vCPU execution via `PATCH /vm` (`Paused`).
    ///
    /// The socket path is derived from the prepared sandbox id, so this
    /// fails closed when no sandbox was prepared or the VMM is unreachable.
    async fn pause_guest_execution(&self) -> BackendResult<()> {
        let sandbox_id = self.base.sandbox_id().await;
        if sandbox_id == "unprepared" {
            return Err(BackendError::Failed {
                operation: BackendOperation::Suspend,
                message: "sandbox must be prepared and booted before suspend".into(),
            });
        }
        let client = FirecrackerApiClient::new(self.api_socket_path(&sandbox_id));
        client.pause_vm().await.map_err(|err| BackendError::Failed {
            operation: BackendOperation::Suspend,
            message: format!("firecracker pause failed: {err}"),
        })
    }

    /// Resumes guest vCPU execution via `PATCH /vm` (`Resumed`).
    async fn resume_guest_execution(&self) -> BackendResult<()> {
        let sandbox_id = self.base.sandbox_id().await;
        if sandbox_id == "unprepared" {
            return Err(BackendError::Failed {
                operation: BackendOperation::Resume,
                message: "sandbox must be suspended before resume".into(),
            });
        }
        let client = FirecrackerApiClient::new(self.api_socket_path(&sandbox_id));
        client
            .resume_vm()
            .await
            .map_err(|err| BackendError::Failed {
                operation: BackendOperation::Resume,
                message: format!("firecracker resume failed: {err}"),
            })
    }

    async fn guest_agent_addr(&self) -> SocketAddr {
        self.network.lock().await.as_ref().map_or(
            self.firecracker_config.guest_agent_addr,
            |network| {
                SocketAddr::new(
                    network.guest_ip.into(),
                    self.firecracker_config.guest_agent_addr.port(),
                )
            },
        )
    }

    async fn configure_logger_when_api_ready(
        &self,
        client: &FirecrackerApiClient,
        log_path: &Path,
        timeout: Duration,
    ) -> Result<()> {
        let log_path = path_to_str(log_path)?.to_owned();
        let deadline = Instant::now() + timeout;
        loop {
            match client.put_logger(&log_path).await {
                Ok(()) => return Ok(()),
                Err(err) => {
                    if let Some(status) = self.vm_exit_status().await? {
                        return Err(SandboxError::Other(format!(
                            "Firecracker exited before API was ready: {status}; logger setup failed: {err}"
                        )));
                    }

                    if Instant::now() >= deadline {
                        return Err(SandboxError::Other(format!(
                            "timed out configuring Firecracker logger at {log_path}: {err}"
                        )));
                    }
                }
            }

            sleep(Duration::from_millis(100)).await;
        }
    }
}

fn enrich_with_firecracker_logs(
    err: SandboxError,
    exit_status: Option<&ExitStatus>,
    vmm_log_path: &Path,
    stdout_log_path: &Path,
    stderr_log_path: &Path,
) -> SandboxError {
    let mut details = Vec::new();
    if let Some(status) = exit_status {
        details.push(format!("Firecracker exit status: {status}"));
    }
    if let Some(tail) = tail_file(vmm_log_path, 20).filter(|tail| !tail.trim().is_empty()) {
        details.push(format!(
            "Firecracker log {}: {}",
            vmm_log_path.display(),
            tail.trim()
        ));
    }
    if let Some(tail) = tail_file(stdout_log_path, 80).filter(|tail| !tail.trim().is_empty()) {
        details.push(format!(
            "Firecracker guest console {}: {}",
            stdout_log_path.display(),
            tail.trim()
        ));
    }
    if let Some(tail) = tail_file(stderr_log_path, 20).filter(|tail| !tail.trim().is_empty()) {
        details.push(format!(
            "Firecracker stderr {}: {}",
            stderr_log_path.display(),
            tail.trim()
        ));
    }

    if details.is_empty() {
        return err;
    }

    SandboxError::Other(format!("{err}; {}", details.join("; ")))
}

fn tail_file(path: &Path, max_lines: usize) -> Option<String> {
    let contents = std::fs::read_to_string(path).ok()?;
    let mut lines = contents.lines().rev().take(max_lines).collect::<Vec<_>>();
    lines.reverse();
    Some(lines.join("\n"))
}

async fn remove_stale_socket(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

async fn wait_for_socket(path: &Path, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if path.exists() {
            return Ok(());
        }

        if Instant::now() >= deadline {
            return Err(SandboxError::Other(format!(
                "timed out waiting for Firecracker API socket {}",
                path.display()
            )));
        }

        sleep(Duration::from_millis(25)).await;
    }
}

fn firecracker_args(arch: Architecture, socket_path: &Path) -> Vec<OsString> {
    let mut args = vec![OsString::from("--api-sock"), socket_path.as_os_str().into()];
    if arch == Architecture::X8664 {
        args.push(OsString::from("--enable-pci"));
    }
    args
}

/// Builds Firecracker jailer arguments with least-privilege hardening.
///
/// Applies namespace isolation, UID/GID drop, chroot, and seccomp
/// level driven by the PicoCompute jailer hardening policy, binding
/// sandbox identity to kernel-level resource namespaces.
fn jailer_args(
    firecracker_bin: &Path,
    arch: Architecture,
    socket_path: &Path,
    sandbox_id: &str,
    jailer_hardening: &crate::firecracker::config::JailerHardening,
) -> Vec<OsString> {
    let mut args = vec![
        OsString::from("--id"),
        OsString::from(sandbox_id),
        OsString::from("--exec-file"),
        firecracker_bin.as_os_str().into(),
    ];

    if let Some(uid) = jailer_hardening.uid {
        args.push(OsString::from("--uid"));
        args.push(OsString::from(uid.to_string()));
    }

    if let Some(gid) = jailer_hardening.gid {
        args.push(OsString::from("--gid"));
        args.push(OsString::from(gid.to_string()));
    }

    if let Some(ref chroot_dir) = jailer_hardening.chroot_base_dir {
        args.push(OsString::from("--chroot-base-dir"));
        args.push(chroot_dir.as_os_str().into());
    }

    if let Some(level) = jailer_hardening.seccomp_level {
        args.push(OsString::from("--seccomp-level"));
        args.push(OsString::from(level.to_string()));
    }

    args.push(OsString::from("--"));
    args.push(OsString::from("--api-sock"));
    args.push(socket_path.as_os_str().into());

    if arch == Architecture::X8664 {
        args.push(OsString::from("--enable-pci"));
    }
    args
}

fn path_to_str(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| SandboxError::Other(format!("path is not valid UTF-8: {}", path.display())))
}

/// Builds the per-boot kernel command line: static base plus the sandbox
/// network identity and the sandbox id. The guest agent reads
/// `pico_sandbox_id=` from `/proc/cmdline` to derive the handshake shared
/// secret; without it the guest falls back to `unknown-sandbox` and proof
/// verification fails (found by a live-boot walk against real Firecracker).
fn kernel_cmdline(
    base: &str,
    sandbox_id: &str,
    network: &NetworkConfig,
) -> std::result::Result<String, String> {
    let base = format!(
        "{base} pico_guest_ip={} pico_guest_prefix={} pico_host_ip={}",
        network.guest_ip, network.prefix_len, network.host_ip
    );
    crate::base::append_sandbox_id_param(&base, sandbox_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use pico_core::RuntimeType;
    use pico_core::runtime::{BackendHealthStatus, PortExposure};

    #[tokio::test]
    async fn boot_requires_prepare_without_changing_state() {
        let adapter = FirecrackerAdapter::new();

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
        let adapter = FirecrackerAdapter::new();

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
        let adapter = FirecrackerAdapter::new();

        let first = adapter.destroy().await.unwrap();
        assert!(first.released.is_empty());

        let second = adapter.destroy().await.unwrap();
        assert!(second.released.is_empty());

        assert_eq!(adapter.state().await.unwrap(), SandboxState::Destroyed);
    }

    #[tokio::test]
    async fn destroy_transitions_to_destroyed_state() {
        let adapter = FirecrackerAdapter::new();

        adapter.destroy().await.unwrap();

        assert_eq!(adapter.state().await.unwrap(), SandboxState::Destroyed);
    }

    #[tokio::test]
    async fn cleanup_delegates_to_destroy() {
        let adapter = FirecrackerAdapter::new();

        let report = adapter.cleanup().await.unwrap();

        assert_eq!(adapter.state().await.unwrap(), SandboxState::Destroyed);
        assert!(report.released.is_empty());
        assert!(report.remaining.is_empty());
    }

    #[tokio::test]
    async fn attach_transport_returns_vsock() {
        let mut config = FirecrackerConfig::detect_defaults();
        config.validate_paths = false;
        let adapter = FirecrackerAdapter::with_config(config);
        adapter
            .base
            .config
            .lock()
            .await
            .replace(sample_sandbox_config());
        *adapter.base.state.lock().await = SandboxState::Running;

        let transport = adapter.attach_transport().await.unwrap();
        match transport {
            GuestTransport::Vsock {
                cid,
                port,
                uds_path,
            } => {
                assert_eq!(cid, 3);
                assert_eq!(port, FirecrackerAdapter::GUEST_AGENT_VSOCK_PORT);
                assert!(
                    uds_path
                        .as_deref()
                        .is_some_and(|path| path.ends_with(".vsock"))
                );
            }
            other => panic!("expected vsock transport, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn attach_transport_requires_running_state() {
        let adapter = FirecrackerAdapter::new();

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

    async fn running_adapter() -> FirecrackerAdapter {
        let mut config = FirecrackerConfig::detect_defaults();
        config.validate_paths = false;
        let adapter = FirecrackerAdapter::with_config(config);
        adapter
            .base
            .config
            .lock()
            .await
            .replace(sample_sandbox_config());
        *adapter.base.state.lock().await = SandboxState::Running;
        adapter
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

    fn sample_sandbox_config() -> SandboxConfig {
        SandboxConfig {
            id: "sbx_fc_test".into(),
            network_isolated: true,
            ..Default::default()
        }
    }

    #[test]
    fn metadata_advertises_expected_capabilities() {
        let metadata = FirecrackerAdapter::new().metadata();

        assert_eq!(metadata.runtime, RuntimeType::Firecracker);
        assert!(metadata.capabilities.contains(BackendCapability::Boot));
        assert!(
            metadata
                .capabilities
                .contains(BackendCapability::GuestTransport)
        );
        assert!(metadata.capabilities.contains(BackendCapability::Exec));
        assert!(metadata.capabilities.contains(BackendCapability::Suspend));
        assert!(metadata.capabilities.contains(BackendCapability::Resume));
        assert!(metadata.capabilities.contains(BackendCapability::Stats));
        assert!(metadata.capabilities.contains(BackendCapability::Health));
        assert!(
            metadata
                .capabilities
                .contains(BackendCapability::Diagnostics)
        );
        assert!(!metadata.capabilities.contains(BackendCapability::Fork));
        assert!(
            !metadata
                .capabilities
                .contains(BackendCapability::BackendManagedPortForwarding)
        );
    }

    #[test]
    fn x86_firecracker_args_enable_pci() {
        let args = firecracker_args(Architecture::X8664, Path::new("/tmp/firecracker.sock"));

        assert!(args.contains(&OsString::from("--enable-pci")));
    }

    #[test]
    fn aarch64_firecracker_args_keep_mmio_transport() {
        let args = firecracker_args(Architecture::Aarch64, Path::new("/tmp/firecracker.sock"));

        assert!(!args.contains(&OsString::from("--enable-pci")));
    }

    #[test]
    fn x86_jailer_args_enable_pci() {
        let args = jailer_args(
            Path::new("/usr/bin/firecracker"),
            Architecture::X8664,
            Path::new("/tmp/firecracker.sock"),
            "sbx_test",
            &crate::firecracker::config::JailerHardening::default(),
        );

        assert!(args.contains(&OsString::from("--id")));
        assert!(args.contains(&OsString::from("sbx_test")));
        assert!(args.contains(&OsString::from("--exec-file")));
        assert!(args.contains(&OsString::from("--enable-pci")));
    }

    #[test]
    fn aarch64_jailer_args_keep_mmio_transport() {
        let args = jailer_args(
            Path::new("/usr/bin/firecracker"),
            Architecture::Aarch64,
            Path::new("/tmp/firecracker.sock"),
            "sbx_test",
            &crate::firecracker::config::JailerHardening::default(),
        );

        assert!(!args.contains(&OsString::from("--enable-pci")));
    }

    #[tokio::test]
    async fn exec_fails_closed_without_sandboxd_session() {
        // Direct adapter exec is not supported: guest sessions are owned by
        // sandboxd over the attached vsock transport.
        let adapter = running_adapter().await;

        let err = adapter
            .exec(exec_req("printf", &["pico-runtime"]))
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            BackendError::Failed {
                operation: BackendOperation::Exec,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn fork_returns_unsupported() {
        let adapter = FirecrackerAdapter::new();

        let error = adapter
            .fork(&SandboxConfig {
                id: "sbx_child".into(),
                ..sample_sandbox_config()
            })
            .await
            .unwrap_err();

        assert!(matches!(error, BackendError::Unsupported { .. }));
    }

    #[tokio::test]
    async fn port_exposure_returns_host_proxy() {
        let adapter = FirecrackerAdapter::new();

        let exposure = adapter.port_exposure(22);
        assert_eq!(exposure, PortExposure::HostProxy);
    }

    #[test]
    fn ssh_username_returns_root() {
        let adapter = FirecrackerAdapter::new();
        assert_eq!(adapter.ssh_username(), "root");
    }

    #[test]
    fn ssh_home_dir_returns_root() {
        let adapter = FirecrackerAdapter::new();
        assert_eq!(adapter.ssh_home_dir(), "/root");
    }

    #[tokio::test]
    async fn stats_returns_state_and_boot_latency() {
        let adapter = FirecrackerAdapter::new();

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
    }

    #[tokio::test]
    async fn health_reports_degraded_when_failed() {
        let adapter = FirecrackerAdapter::new();
        *adapter.base.state.lock().await = SandboxState::Failed;

        let health = adapter.health().await.unwrap();

        assert_eq!(health.status, BackendHealthStatus::Degraded);
        assert!(health.message.is_some_and(|m| m.contains("failed")));
    }

    #[tokio::test]
    async fn health_reports_unavailable_when_destroyed() {
        let adapter = FirecrackerAdapter::new();
        *adapter.base.state.lock().await = SandboxState::Destroyed;

        let health = adapter.health().await.unwrap();

        assert_eq!(health.status, BackendHealthStatus::Unavailable);
        assert!(health.message.is_some_and(|m| m.contains("destroyed")));
    }

    #[tokio::test]
    async fn health_reports_ready_when_pending() {
        let adapter = FirecrackerAdapter::new();

        let health = adapter.health().await.unwrap();

        assert_eq!(health.status, BackendHealthStatus::Ready);
    }

    #[tokio::test]
    async fn diagnostics_includes_log_artifacts() {
        let adapter = FirecrackerAdapter::new();

        let bundle = adapter.diagnostics().await.unwrap();

        assert!(bundle.summary.contains("Firecracker backend state"));
        assert_eq!(bundle.artifacts.len(), 3);
        assert!(
            bundle
                .artifacts
                .iter()
                .any(|a| a.contains("firecracker.stdout.log"))
        );
        assert!(
            bundle
                .artifacts
                .iter()
                .any(|a| a.contains("firecracker.stderr.log"))
        );
        assert!(
            bundle
                .artifacts
                .iter()
                .any(|a| a.contains("firecracker.vmm.log"))
        );
    }

    #[tokio::test]
    async fn port_addr_returns_none_when_not_running() {
        let adapter = FirecrackerAdapter::new();

        let addr = adapter.port_addr(8080).await.unwrap();

        assert!(addr.is_none());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires Firecracker binary and TAP networking"]
    async fn conformance_lifecycle_reports_direct_exec_unsupported() {
        // Direct adapter exec is owned by sandboxd; the conformance runner
        // exercises prepare/boot/attach/wait-ready/destroy through the
        // adapter and exec through the supervisor session.
        let adapter = running_adapter().await;

        let err = adapter.exec(exec_req("true", &[])).await.unwrap_err();

        assert!(matches!(
            err,
            BackendError::Failed {
                operation: BackendOperation::Exec,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn prepare_sets_state_to_preparing() {
        let mut config = FirecrackerConfig::detect_defaults();
        config.validate_paths = false;
        let adapter = FirecrackerAdapter::with_config(config);

        let _ = adapter.prepare(&sample_sandbox_config()).await.unwrap();

        assert_eq!(adapter.state().await.unwrap(), SandboxState::Preparing);
    }

    #[tokio::test]
    async fn prepare_records_api_socket_not_tap() {
        let mut config = FirecrackerConfig::detect_defaults();
        config.validate_paths = false;
        let adapter = FirecrackerAdapter::with_config(config);

        let prepared = adapter.prepare(&sample_sandbox_config()).await.unwrap();

        assert!(
            prepared.resources.iter().any(|r| r.class == "api-socket"),
            "Firecracker still owns the API socket: {:?}",
            prepared.resources
        );
        assert!(
            prepared.resources.iter().all(|r| r.class != "tap"),
            "TAP receipts belong to network-agent, not the adapter: {:?}",
            prepared.resources
        );
    }

    #[tokio::test]
    async fn conformance_capability_declarations_match_firecracker_lifecycle() {
        let mut config = FirecrackerConfig::detect_defaults();
        config.validate_paths = false;
        let adapter = FirecrackerAdapter::with_config(config);

        let metadata = adapter.metadata();

        // Firecracker declares Boot, GuestTransport, GuestReadiness, Exec,
        // Suspend, Resume, SnapshotRestore, Stats, Health, Diagnostics.
        let expected = BackendCapabilities::from([
            BackendCapability::Boot,
            BackendCapability::GuestTransport,
            BackendCapability::GuestReadiness,
            BackendCapability::Exec,
            BackendCapability::Suspend,
            BackendCapability::Resume,
            BackendCapability::SnapshotRestore,
            BackendCapability::Stats,
            BackendCapability::Health,
            BackendCapability::Diagnostics,
        ]);
        assert_eq!(metadata.capabilities, expected);

        // Unsupported capabilities must be explicitly absent from declarations.
        assert!(!metadata.capabilities.contains(BackendCapability::Fork));
        assert!(
            !metadata
                .capabilities
                .contains(BackendCapability::BackendManagedPortForwarding)
        );

        // Unsupported operations return Unsupported error (not silent skip).
        let fork_err = adapter
            .fork(&SandboxConfig {
                id: "sbx_fc_fork".into(),
                network_isolated: true,
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert!(matches!(fork_err, BackendError::Unsupported { .. }));

        // SSH and port defaults are consistent.
        assert_eq!(adapter.ssh_username(), "root");
        assert_eq!(adapter.ssh_home_dir(), "/root");
        assert_eq!(adapter.port_exposure(22), PortExposure::HostProxy);
        assert!(
            !adapter
                .port_exposure(8080)
                .eq(&PortExposure::BackendManaged)
        );

        // State is inspectable without side effects.
        let state = adapter.state().await.unwrap();
        assert!(matches!(state, SandboxState::Pending));
    }

    #[test]
    fn kernel_cmdline_carries_network_identity_and_sandbox_id() {
        let network = crate::firecracker::config::NetworkConfig::for_sandbox_id("sbx-live-test");
        let cmdline = kernel_cmdline("console=ttyS0 root=/dev/vda", "sbx-live-test", &network)
            .expect("valid id must be accepted");
        assert!(cmdline.starts_with("console=ttyS0 root=/dev/vda "));
        assert!(
            cmdline.contains(&format!("pico_guest_ip={}", network.guest_ip)),
            "guest IP missing: {cmdline}"
        );
        assert!(
            cmdline.contains("pico_sandbox_id=sbx-live-test"),
            "sandbox id missing (guest falls back to unknown-sandbox and proof fails): {cmdline}"
        );
    }

    #[test]
    fn kernel_cmdline_rejects_hostile_sandbox_id() {
        let network = crate::firecracker::config::NetworkConfig::for_sandbox_id("sbx-live-test");
        let err = kernel_cmdline("console=ttyS0", "sbx_x init=/bin/sh", &network)
            .expect_err("whitespace id must be rejected");
        assert!(err.contains("single token"), "unexpected error: {err}");
    }

    #[test]
    fn jailer_hardening_args_include_uid_when_set() {
        let hardening = crate::firecracker::config::JailerHardening {
            uid: Some(1000),
            gid: None,
            chroot_base_dir: None,
            seccomp_level: None,
        };

        let args = jailer_args(
            Path::new("/usr/bin/firecracker"),
            Architecture::Aarch64,
            Path::new("/tmp/firecracker.sock"),
            "sbx_test",
            &hardening,
        );

        assert!(args.contains(&OsString::from("--uid")));
        assert!(args.contains(&OsString::from("1000")));
        assert!(!args.contains(&OsString::from("--gid")));
    }

    #[test]
    fn jailer_hardening_args_include_gid_when_set() {
        let hardening = crate::firecracker::config::JailerHardening {
            uid: None,
            gid: Some(1000),
            chroot_base_dir: None,
            seccomp_level: None,
        };

        let args = jailer_args(
            Path::new("/usr/bin/firecracker"),
            Architecture::Aarch64,
            Path::new("/tmp/firecracker.sock"),
            "sbx_test",
            &hardening,
        );

        assert!(args.contains(&OsString::from("--gid")));
        assert!(args.contains(&OsString::from("1000")));
        assert!(!args.contains(&OsString::from("--uid")));
    }

    #[test]
    fn jailer_hardening_args_include_chroot_when_set() {
        let hardening = crate::firecracker::config::JailerHardening {
            uid: None,
            gid: None,
            chroot_base_dir: Some(PathBuf::from("/srv/jailer")),
            seccomp_level: None,
        };

        let args = jailer_args(
            Path::new("/usr/bin/firecracker"),
            Architecture::Aarch64,
            Path::new("/tmp/firecracker.sock"),
            "sbx_test",
            &hardening,
        );

        assert!(args.contains(&OsString::from("--chroot-base-dir")));
        assert!(args.contains(&OsString::from("/srv/jailer")));
    }

    #[test]
    fn jailer_hardening_args_include_seccomp_level_when_set() {
        let hardening = crate::firecracker::config::JailerHardening {
            uid: None,
            gid: None,
            chroot_base_dir: None,
            seccomp_level: Some(2),
        };

        let args = jailer_args(
            Path::new("/usr/bin/firecracker"),
            Architecture::Aarch64,
            Path::new("/tmp/firecracker.sock"),
            "sbx_test",
            &hardening,
        );

        assert!(args.contains(&OsString::from("--seccomp-level")));
        assert!(args.contains(&OsString::from("2")));
    }

    #[test]
    fn jailer_hardening_defaults_are_all_none() {
        let hardening = crate::firecracker::config::JailerHardening::default();

        assert!(hardening.uid.is_none());
        assert!(hardening.gid.is_none());
        assert!(hardening.chroot_base_dir.is_none());
        assert!(hardening.seccomp_level.is_none());
        assert!(!hardening.is_enabled());
    }

    #[test]
    fn jailer_hardening_is_enabled_when_any_option_set() {
        let hardening = crate::firecracker::config::JailerHardening {
            uid: Some(0),
            gid: None,
            chroot_base_dir: None,
            seccomp_level: None,
        };
        assert!(hardening.is_enabled());
    }

    #[test]
    fn jailer_hardening_production_defaults_include_chroot() {
        let hardening = crate::firecracker::config::JailerHardening::production_defaults(
            PathBuf::from("/srv/jailer"),
        );

        assert_eq!(hardening.uid, Some(65534));
        assert_eq!(hardening.gid, Some(65534));
        assert!(hardening.chroot_base_dir.is_some());
        assert_eq!(hardening.seccomp_level, Some(2));
        assert!(hardening.is_enabled());
    }

    struct RecordedApiRequest {
        method: String,
        path: String,
        body: String,
    }

    /// Spawns a single-shot mock Firecracker API server on the adapter's
    /// socket path. Returns the recorded request once handled.
    async fn spawn_mock_firecracker_api(
        socket_path: PathBuf,
        status: u16,
    ) -> tokio::sync::oneshot::Receiver<RecordedApiRequest> {
        let listener = tokio::net::UnixListener::bind(&socket_path)
            .unwrap_or_else(|err| panic!("bind mock Firecracker socket: {err}"));
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.expect("accept mock request");
            let mut raw = Vec::new();
            let mut buf = [0_u8; 4096];
            // Read until headers plus the declared body are present.
            let body_len = loop {
                use tokio::io::AsyncReadExt as _;
                let n = conn.read(&mut buf).await.expect("read mock request");
                if n == 0 {
                    break 0;
                }
                raw.extend_from_slice(&buf[..n]);
                if let Some(header_end) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                    let header = std::str::from_utf8(&raw[..header_end])
                        .expect("mock request headers are UTF-8");
                    let mut len = 0;
                    for line in header.lines().skip(1) {
                        if let Some((name, value)) = line.split_once(':')
                            && name.eq_ignore_ascii_case("content-length")
                        {
                            len = value.trim().parse().expect("mock content-length");
                        }
                    }
                    if raw.len() >= header_end + 4 + len {
                        break len;
                    }
                }
            };
            let text = std::str::from_utf8(&raw).expect("mock request is UTF-8");
            let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text, ""));
            let mut parts = head.lines().next().unwrap_or("").split_whitespace();
            let recorded = RecordedApiRequest {
                method: parts.next().unwrap_or("").into(),
                path: parts.next().unwrap_or("").into(),
                body: body.get(..body_len).unwrap_or("").into(),
            };
            let response = if (200..300).contains(&status) {
                format!("HTTP/1.1 {status} OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            } else {
                let fault = r#"{"fault_message":"mock failure"}"#;
                format!(
                    "HTTP/1.1 {status} Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{fault}",
                    fault.len()
                )
            };
            use tokio::io::AsyncWriteExt as _;
            conn.write_all(response.as_bytes())
                .await
                .expect("write mock response");
            let _ = tx.send(recorded);
        });
        rx
    }

    async fn suspend_test_adapter(
        socket_dir: &std::path::Path,
        state: SandboxState,
    ) -> FirecrackerAdapter {
        let mut config = FirecrackerConfig::detect_defaults();
        config.validate_paths = false;
        config.api_socket_dir = socket_dir.to_path_buf();
        let adapter = FirecrackerAdapter::with_config(config);
        adapter.prepare(&sample_sandbox_config()).await.unwrap();
        *adapter.base.state.lock().await = state;
        adapter
    }

    fn suspend_socket_path(socket_dir: &std::path::Path) -> PathBuf {
        socket_dir.join("sbx_fc_test.firecracker.sock")
    }

    #[tokio::test]
    async fn suspend_pauses_guest_via_patch_vm() {
        let tmp = tempfile::tempdir().unwrap();
        let adapter = suspend_test_adapter(tmp.path(), SandboxState::Running).await;
        let rx = spawn_mock_firecracker_api(suspend_socket_path(tmp.path()), 204).await;

        adapter.suspend().await.unwrap();

        assert_eq!(adapter.state().await.unwrap(), SandboxState::Suspended);
        let recorded = rx.await.expect("mock server records request");
        assert_eq!(recorded.method, "PATCH");
        assert_eq!(recorded.path, "/vm");
        assert!(
            recorded.body.contains("\"Paused\""),
            "body: {}",
            recorded.body
        );
    }

    #[tokio::test]
    async fn resume_resumes_guest_via_patch_vm() {
        let tmp = tempfile::tempdir().unwrap();
        let adapter = suspend_test_adapter(tmp.path(), SandboxState::Suspended).await;
        let rx = spawn_mock_firecracker_api(suspend_socket_path(tmp.path()), 204).await;

        adapter.resume().await.unwrap();

        assert_eq!(adapter.state().await.unwrap(), SandboxState::Running);
        let recorded = rx.await.expect("mock server records request");
        assert_eq!(recorded.method, "PATCH");
        assert_eq!(recorded.path, "/vm");
        assert!(
            recorded.body.contains("\"Resumed\""),
            "body: {}",
            recorded.body
        );
    }

    #[tokio::test]
    async fn suspend_failure_reverts_to_running() {
        let tmp = tempfile::tempdir().unwrap();
        let adapter = suspend_test_adapter(tmp.path(), SandboxState::Running).await;
        let rx = spawn_mock_firecracker_api(suspend_socket_path(tmp.path()), 400).await;

        let error = adapter.suspend().await.unwrap_err();

        assert!(
            matches!(
                error,
                BackendError::Failed {
                    operation: BackendOperation::Suspend,
                    ..
                }
            ),
            "expected Failed(Suspend), got: {error}"
        );
        assert_eq!(adapter.state().await.unwrap(), SandboxState::Running);
        let recorded = rx.await.expect("mock server records request");
        assert_eq!(recorded.method, "PATCH");
        assert_eq!(recorded.path, "/vm");
    }

    #[tokio::test]
    async fn resume_failure_reverts_to_suspended() {
        let tmp = tempfile::tempdir().unwrap();
        let adapter = suspend_test_adapter(tmp.path(), SandboxState::Suspended).await;
        let rx = spawn_mock_firecracker_api(suspend_socket_path(tmp.path()), 400).await;

        let error = adapter.resume().await.unwrap_err();

        assert!(
            matches!(
                error,
                BackendError::Failed {
                    operation: BackendOperation::Resume,
                    ..
                }
            ),
            "expected Failed(Resume), got: {error}"
        );
        assert_eq!(adapter.state().await.unwrap(), SandboxState::Suspended);
        let recorded = rx.await.expect("mock server records request");
        assert_eq!(recorded.method, "PATCH");
        assert_eq!(recorded.path, "/vm");
    }

    #[tokio::test]
    async fn suspend_without_vmm_socket_fails_without_suspending() {
        let tmp = tempfile::tempdir().unwrap();
        let adapter = suspend_test_adapter(tmp.path(), SandboxState::Running).await;
        // No mock server is bound, so the API connect fails.

        let error = adapter.suspend().await.unwrap_err();

        assert!(
            matches!(
                error,
                BackendError::Failed {
                    operation: BackendOperation::Suspend,
                    ..
                }
            ),
            "expected Failed(Suspend), got: {error}"
        );
        assert_eq!(adapter.state().await.unwrap(), SandboxState::Running);
    }

    #[tokio::test]
    async fn suspend_of_suspended_is_idempotent() {
        let adapter = FirecrackerAdapter::new();
        *adapter.base.state.lock().await = SandboxState::Suspended;

        adapter.suspend().await.unwrap();

        assert_eq!(adapter.state().await.unwrap(), SandboxState::Suspended);
    }

    #[tokio::test]
    async fn resume_of_running_is_idempotent() {
        let adapter = FirecrackerAdapter::new();
        *adapter.base.state.lock().await = SandboxState::Running;

        adapter.resume().await.unwrap();

        assert_eq!(adapter.state().await.unwrap(), SandboxState::Running);
    }

    #[tokio::test]
    async fn suspend_requires_running_state() {
        let adapter = FirecrackerAdapter::new();

        let error = adapter.suspend().await.unwrap_err();

        assert!(matches!(
            error,
            BackendError::InvalidState {
                operation: BackendOperation::Suspend,
                actual: SandboxState::Pending,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn resume_requires_suspended_state() {
        let adapter = FirecrackerAdapter::new();

        let error = adapter.resume().await.unwrap_err();

        assert!(matches!(
            error,
            BackendError::InvalidState {
                operation: BackendOperation::Resume,
                actual: SandboxState::Pending,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn restore_snapshot_rejects_extra_blob_paths() {
        let adapter = FirecrackerAdapter::new();
        *adapter.base.state.lock().await = SandboxState::Running;

        let ctx = BackendRestoreContext {
            snapshot_id: "snap_test".into(),
            sandbox_id: "sbx_fc_test".into(),
            blob_paths: vec![
                PathBuf::from("/tmp/mem"),
                PathBuf::from("/tmp/vmstate"),
                PathBuf::from("/tmp/extra"),
            ],
        };

        let error = adapter.restore_snapshot(&ctx).await.unwrap_err();
        assert_blob_count_rejected(error);
    }

    #[tokio::test]
    async fn restore_snapshot_rejects_missing_blob_paths() {
        let adapter = FirecrackerAdapter::new();
        *adapter.base.state.lock().await = SandboxState::Running;

        let ctx = BackendRestoreContext {
            snapshot_id: "snap_test".into(),
            sandbox_id: "sbx_fc_test".into(),
            blob_paths: vec![PathBuf::from("/tmp/mem")],
        };

        let error = adapter.restore_snapshot(&ctx).await.unwrap_err();
        assert_blob_count_rejected(error);
    }

    fn assert_blob_count_rejected(error: BackendError) {
        match error {
            BackendError::Failed {
                operation: BackendOperation::RestoreSnapshot,
                message,
            } => {
                assert!(
                    message.contains("exactly two blob paths"),
                    "expected length-guard message, got: {message}"
                );
            }
            other => panic!("expected Failed(RestoreSnapshot), got: {other}"),
        }
    }
}

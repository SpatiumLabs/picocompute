//! QEMU-backed implementation of the runtime adapter trait.

pub mod config;

use std::fs::File;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::net::TcpStream;
use tokio::process::Command;
use tokio::sync::Mutex;
use tokio::time::{Instant, sleep};

use pico_core::Result;
use pico_core::cpu_isolation::apply_cpu_affinity;
use pico_core::runtime::{
    BackendCapabilities, BackendCapability, BackendError, BackendHealth, BackendHealthStatus,
    BackendMetadata, BackendOperation, BackendResult, BackendStats, CleanupReport,
    DiagnosticBundle, ForkResult, GuestTransport, PortExposure, PreparedSandbox, ResourceReceipt,
    RuntimeBackend,
};
use pico_core::{ExecRequest, ExecResponse, SandboxConfig, SandboxError, SandboxState};
use pico_core::{apply_service_class_sched_policy, is_sched_permission_denied};

use crate::base::VmBackendBase;
use crate::qemu::config::{QemuConfig, QemuMode};

pub struct QemuAdapter {
    base: VmBackendBase,
    vm_process: Arc<Mutex<Option<tokio::process::Child>>>,
    guest_agent_addr: Arc<Mutex<Option<SocketAddr>>>,
    qmp_addr: Arc<Mutex<Option<SocketAddr>>>,
    qemu_config: QemuConfig,
    log_dir: PathBuf,
}

impl Default for QemuAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl QemuAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: VmBackendBase::new(),
            vm_process: Arc::new(Mutex::new(None)),
            guest_agent_addr: Arc::new(Mutex::new(None)),
            qmp_addr: Arc::new(Mutex::new(None)),
            qemu_config: QemuConfig::detect_defaults(),
            log_dir: default_log_dir(),
        }
    }

    #[must_use]
    pub fn with_config(qemu_config: QemuConfig) -> Self {
        Self {
            base: VmBackendBase::new(),
            vm_process: Arc::new(Mutex::new(None)),
            guest_agent_addr: Arc::new(Mutex::new(None)),
            qmp_addr: Arc::new(Mutex::new(None)),
            qemu_config,
            log_dir: default_log_dir(),
        }
    }

    fn stdout_log_path(&self, sandbox_id: &str) -> PathBuf {
        self.log_dir.join(format!("{sandbox_id}-stdout.log"))
    }

    fn stderr_log_path(&self, sandbox_id: &str) -> PathBuf {
        self.log_dir.join(format!("{sandbox_id}-stderr.log"))
    }

    async fn kill_vm_process(&self) -> Result<()> {
        let mut vm_proc = self.vm_process.lock().await;
        if let Some(mut child) = vm_proc.take() {
            if let Err(err) = child.kill().await {
                tracing::debug!("kill QEMU process failed (may already be dead): {err}");
            }
            let _ = child.wait().await;
        }
        Ok(())
    }

    async fn vm_exit_status(&self) -> Result<Option<std::process::ExitStatus>> {
        let mut vm_proc = self.vm_process.lock().await;
        match vm_proc.as_mut() {
            Some(child) => child.try_wait().map_err(Into::into),
            None => Ok(None),
        }
    }

    async fn send_qmp_command(&self, cmd: &str) -> Result<()> {
        let addr = self
            .qmp_addr
            .lock()
            .await
            .ok_or_else(|| SandboxError::Other("QMP address not available".into()))?;

        // The QMP listener opens after QEMU's main loop is up, which lags
        // spawn by ~1-2s on healthy hosts and more on slow ones; dialing once
        // races startup and mistakes a booting VM for a broken one (found by
        // the live-boot walk dialing 4ms after spawn). Retry until the
        // deadline, fail closed after it, and fail fast when the VM process
        // is already gone instead of burning the whole deadline.
        const QMP_DIAL_DEADLINE_SECS: u64 = 30;
        let deadline = Instant::now() + Duration::from_secs(QMP_DIAL_DEADLINE_SECS);
        let stream =
            loop {
                let dial_err: Option<String> =
                    match tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(addr))
                        .await
                    {
                        Ok(Ok(stream)) => break stream,
                        Ok(Err(err)) => Some(err.to_string()),
                        Err(_) => Some("dial timed out".to_string()),
                    };
                if let Some(status) = self.vm_exit_status().await.map_err(|e| {
                    SandboxError::Other(format!("QMP dial status check failed: {e}"))
                })? {
                    return Err(SandboxError::Other(format!(
                        "QMP dial to {addr} failed: QEMU exited with {status}"
                    )));
                }
                if Instant::now() >= deadline {
                    return Err(SandboxError::Other(format!(
                        "connect QMP at {addr} failed after {QMP_DIAL_DEADLINE_SECS}s: {}",
                        dial_err
                            .unwrap_or_else(|| "listener not accepting connections".to_string())
                    )));
                }
                sleep(Duration::from_millis(200)).await;
            };

        // Read one JSON response from the QMP socket. `readable()` may wake
        // spuriously, so a WouldBlock `try_read` re-arms instead of failing.
        async fn read_qmp(stream: &TcpStream, context: &str) -> Result<serde_json::Value> {
            let mut buf = vec![0u8; 4096];
            for _ in 0..10 {
                tokio::time::timeout(Duration::from_secs(3), stream.readable())
                    .await
                    .map_err(|_| SandboxError::Other(format!("timeout reading QMP {context}")))?
                    .map_err(|err| SandboxError::Other(format!("QMP ready {context}: {err}")))?;
                match stream.try_read(&mut buf) {
                    Ok(n) => {
                        return serde_json::from_slice(&buf[..n]).map_err(|err| {
                            SandboxError::Other(format!("parse QMP {context}: {err}"))
                        });
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(err) => {
                        return Err(SandboxError::Other(format!("read QMP {context}: {err}")));
                    }
                }
            }
            Err(SandboxError::Other(format!(
                "read QMP {context}: spurious readiness without data"
            )))
        }

        // Read QMP greeting and verify it is a valid QMP session
        let greeting = read_qmp(&stream, "greeting").await?;
        if greeting.get("QMP").is_none() {
            return Err(SandboxError::Other(format!(
                "unexpected QMP greeting, missing QMP key: {greeting}"
            )));
        }

        // Send qmp_capabilities and check response for errors
        let caps_cmd = b"{\"execute\":\"qmp_capabilities\"}\n";
        stream
            .try_write(caps_cmd)
            .map_err(|err| SandboxError::Other(format!("write QMP capabilities: {err}")))?;
        let caps_resp = read_qmp(&stream, "capabilities response").await?;
        if let Some(error) = caps_resp.get("error") {
            return Err(SandboxError::Other(format!(
                "QMP capabilities negotiation failed: {error}"
            )));
        }

        // Send the actual command (stop/cont) and check the response for errors
        let cmd_bytes = format!("{{ \"execute\": \"{cmd}\" }}\n");
        stream
            .try_write(cmd_bytes.as_bytes())
            .map_err(|err| SandboxError::Other(format!("write QMP {cmd}: {err}")))?;
        let cmd_resp = read_qmp(&stream, &format!("{cmd} response")).await?;
        if let Some(error) = cmd_resp.get("error") {
            return Err(SandboxError::Other(format!("QMP {cmd} failed: {error}")));
        }

        Ok(())
    }
}

#[async_trait]
impl RuntimeBackend for QemuAdapter {
    fn metadata(&self) -> BackendMetadata {
        BackendMetadata {
            runtime: pico_core::RuntimeType::Qemu,
            version: env!("CARGO_PKG_VERSION").into(),
            capabilities: BackendCapabilities::from([
                BackendCapability::Boot,
                BackendCapability::GuestTransport,
                BackendCapability::GuestReadiness,
                BackendCapability::Exec,
                BackendCapability::Suspend,
                BackendCapability::Resume,
                BackendCapability::Stats,
                BackendCapability::Health,
                BackendCapability::Diagnostics,
                BackendCapability::BackendManagedPortForwarding,
            ]),
        }
    }

    #[tracing::instrument(skip(self, config), fields(sandbox_id = %config.id))]
    async fn prepare(&self, config: &SandboxConfig) -> BackendResult<PreparedSandbox> {
        tracing::info!("Preparing QEMU resources for sandbox {}", config.id);
        let qemu_cfg = &self.qemu_config;

        if qemu_cfg.validate_paths || qemu_cfg.mode == QemuMode::Production {
            if !qemu_cfg.kernel.image_path.exists() {
                return Err(BackendError::Failed {
                    operation: BackendOperation::Prepare,
                    message: format!(
                        "kernel image not found at {}",
                        qemu_cfg.kernel.image_path.display()
                    ),
                });
            }
            if !qemu_cfg.rootfs_path.exists() {
                return Err(BackendError::Failed {
                    operation: BackendOperation::Prepare,
                    message: format!("rootfs not found at {}", qemu_cfg.rootfs_path.display()),
                });
            }
        }

        {
            let mut cfg = self.base.config.lock().await;
            *cfg = Some(config.clone());
        }
        {
            let mut state = self.base.state.lock().await;
            *state = SandboxState::Preparing;
        }

        let receipts = vec![ResourceReceipt {
            class: "vm-process".into(),
            name: format!("qemu-{}", config.id),
            external_id: None,
        }];
        Ok(PreparedSandbox {
            resources: receipts,
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
        let mut qemu_cfg = self.qemu_config.clone();
        qemu_cfg
            .validate_for_start()
            .map_err(|err| BackendError::Failed {
                operation: BackendOperation::Boot,
                message: err,
            })?;
        let guest_agent_addr =
            allocate_guest_agent_addr(qemu_cfg.guest_agent_addr).map_err(|err| {
                BackendError::Failed {
                    operation: BackendOperation::Boot,
                    message: err.to_string(),
                }
            })?;
        let qmp_addr = if qemu_cfg.qmp_enabled {
            Some(allocate_guest_agent_addr(qemu_cfg.qmp_addr).map_err(|err| {
                BackendError::Failed {
                    operation: BackendOperation::Boot,
                    message: format!("allocate QMP address: {err}"),
                }
            })?)
        } else {
            None
        };
        // The `-qmp` command line must carry the allocated address, not the
        // `:0` placeholder from config: QEMU listens where told, while
        // suspend dials the stored allocation. Passing `:0` through left QMP
        // unreachable (found by a live-boot walk against real QEMU).
        if let Some(addr) = qmp_addr {
            qemu_cfg.qmp_addr = addr;
        }
        // The guest agent derives the handshake secret from `pico_sandbox_id=`
        // on the kernel command line (same contract as Firecracker); without it
        // the guest falls back to `unknown-sandbox` and proof verification fails.
        qemu_cfg.kernel.cmdline =
            crate::base::append_sandbox_id_param(&qemu_cfg.kernel.cmdline, &sandbox_config.id)
                .map_err(|err| BackendError::Failed {
                    operation: BackendOperation::Boot,
                    message: format!("invalid sandbox identity for kernel cmdline: {err}"),
                })?;
        let mut args =
            qemu_cfg.command_args_for_guest_agent(guest_agent_addr, sandbox_config.ssh_port);
        if qemu_cfg.enable_vsock {
            args.extend(qemu_cfg.vsock_device_args(&sandbox_config.id));
        } else if qemu_cfg.serial_fallback {
            let serial_path = qemu_cfg.serial_socket_path(&sandbox_config.id);
            if let Some(parent) = serial_path.parent() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .map_err(|err| BackendError::Failed {
                        operation: BackendOperation::Boot,
                        message: format!(
                            "create QEMU serial socket directory {}: {err}",
                            parent.display()
                        ),
                    })?;
            }
            match tokio::fs::remove_file(&serial_path).await {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    return Err(BackendError::Failed {
                        operation: BackendOperation::Boot,
                        message: format!(
                            "failed to remove stale serial socket {}: {err}",
                            serial_path.display()
                        ),
                    });
                }
            }
            args.extend(qemu_cfg.serial_device_args(&sandbox_config.id));
        }

        tracing::info!(
            "Starting QEMU VM (sandbox={}, arch={:?}, kernel={}, rootfs={}, guest_agent={}, vsock={}, serial_fallback={})",
            sandbox_config.id,
            qemu_cfg.arch,
            qemu_cfg.kernel.image_path.display(),
            qemu_cfg.rootfs_path.display(),
            guest_agent_addr,
            qemu_cfg.enable_vsock,
            qemu_cfg.serial_fallback,
        );

        let stdout_log_path = self.stdout_log_path(&sandbox_config.id);
        let stderr_log_path = self.stderr_log_path(&sandbox_config.id);

        if let Some(parent) = stdout_log_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|err| BackendError::Failed {
                    operation: BackendOperation::Boot,
                    message: format!("create QEMU log directory {}: {err}", parent.display()),
                })?;
        }

        let stdout_log = File::create(&stdout_log_path).map_err(|err| BackendError::Failed {
            operation: BackendOperation::Boot,
            message: format!(
                "create QEMU stdout log {}: {err}",
                stdout_log_path.display()
            ),
        })?;

        let stderr_log = File::create(&stderr_log_path).map_err(|err| BackendError::Failed {
            operation: BackendOperation::Boot,
            message: format!(
                "create QEMU stderr log {}: {err}",
                stderr_log_path.display()
            ),
        })?;

        let start_result: Result<()> = async {
            apply_qemu_hardening(&qemu_cfg.hardening)
                .map_err(|err| SandboxError::Other(format!("QEMU hardening failed: {err}")))?;

            let child = Command::new(&qemu_cfg.qemu_binary_path)
                .args(&args)
                .stdin(Stdio::null())
                .stdout(Stdio::from(stdout_log))
                .stderr(Stdio::from(stderr_log))
                .spawn()
                .map_err(|err| {
                    SandboxError::Other(format!(
                        "failed to launch QEMU binary {}: {err}",
                        qemu_cfg.qemu_binary_path.display()
                    ))
                })?;

            {
                let mut vm_proc = self.vm_process.lock().await;
                *vm_proc = Some(child);
            }

            // Apply CPU pinning if configured
            {
                let sandbox_config = self.base.config.lock().await;
                if let Some(cpu_set) = sandbox_config.as_ref().and_then(|c| c.cpu_set.as_ref()) {
                    let vm_proc = self.vm_process.lock().await;
                    if let Some(ref child) = *vm_proc
                        && let Some(pid) = child.id()
                        && let Err(err) = apply_cpu_affinity(
                            pid,
                            &pico_core::cpu_isolation::CpuSet::new(cpu_set.iter().copied())
                                .unwrap_or_else(|| {
                                    pico_core::cpu_isolation::CpuSet::new([0]).unwrap()
                                }),
                        )
                    {
                        tracing::warn!(
                            pid = pid,
                            error = %err,
                            "failed to apply CPU pinning to QEMU VMM process"
                        );
                    }
                }
            }
            // Apply the service-class scheduling policy to the VMM pid at
            // spawn (LS no-op, BE SCHED_IDLE). Permission-denied warns;
            // other control failures fail boot closed.
            {
                let sandbox_config = self.base.config.lock().await;
                if let Some(cfg) = sandbox_config.as_ref()
                    && cfg.service_class.is_best_effort()
                {
                    let vm_proc = self.vm_process.lock().await;
                    if let Some(ref child) = *vm_proc
                        && let Some(pid) = child.id()
                        && let Err(err) =
                            apply_service_class_sched_policy(cfg.service_class, pid)
                    {
                        if is_sched_permission_denied(&err) {
                            tracing::warn!(
                                pid = pid,
                                error = %err,
                                "sched policy denied for QEMU VMM process; continuing at default priority"
                            );
                        } else {
                            return Err(SandboxError::Other(format!(
                                "sched policy failed for QEMU VMM pid {pid}: {err}"
                            )));
                        }
                    }
                }
            }
            {
                let mut addr = self.guest_agent_addr.lock().await;
                *addr = Some(guest_agent_addr);
            }
            if let Some(qmp) = qmp_addr {
                let mut addr = self.qmp_addr.lock().await;
                *addr = Some(qmp);
            }

            // Check for immediate process exit
            if let Some(status) = self.vm_exit_status().await? {
                return Err(SandboxError::Other(format!(
                    "QEMU exited immediately after launch: {status}"
                )));
            }

            Ok(())
        }
        .await;

        if let Err(err) = start_result {
            let exit_status = self.vm_exit_status().await.ok().flatten();
            let _ = self.kill_vm_process().await;
            let err = enrich_with_qemu_logs(
                err,
                exit_status.as_ref(),
                &stdout_log_path,
                &stderr_log_path,
            );
            {
                let mut state = self.base.state.lock().await;
                *state = SandboxState::Failed;
            }
            *self.base.boot_latency_ms.lock().await = Some(boot_start.elapsed().as_millis() as u64);
            return Err(BackendError::Failed {
                operation: BackendOperation::Boot,
                message: err.to_string(),
            });
        }

        {
            *self.base.boot_latency_ms.lock().await = Some(boot_start.elapsed().as_millis() as u64);
            let mut state = self.base.state.lock().await;
            *state = SandboxState::Running;
        }
        tracing::info!(
            "QEMU VM booted in {}ms",
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
        if self.qemu_config.enable_vsock {
            let sandbox_id = self.base.sandbox_id().await;
            return Ok(GuestTransport::Vsock {
                cid: self.qemu_config.guest_cid_for_sandbox(&sandbox_id),
                port: self.qemu_config.vsock_port,
                uds_path: None,
            });
        }
        if self.qemu_config.serial_fallback {
            let sandbox_id = self.base.sandbox_id().await;
            return Ok(GuestTransport::Unix {
                path: self
                    .qemu_config
                    .serial_socket_path(&sandbox_id)
                    .display()
                    .to_string(),
            });
        }
        // Production uses vsock; compatibility uses the Unix serial
        // fallback. Fail closed when neither is enabled.
        return Err(BackendError::IncompleteSetup {
            operation: BackendOperation::AttachTransport,
            message: "QEMU requires vsock or serial fallback".into(),
        });
    }

    async fn wait_ready(&self, transport: &GuestTransport) -> BackendResult<()> {
        match transport {
            // Production transports (vsock, virtio-serial Unix socket) are
            // authenticated by sandboxd's session handshake, which owns
            // readiness. The adapter only records the running state here,
            // mirroring Firecracker.
            GuestTransport::Vsock { .. } | GuestTransport::Unix { .. } => {
                *self.base.state.lock().await = SandboxState::Running;
                Ok(())
            }
        }
    }

    #[tracing::instrument(skip(self))]
    async fn destroy(&self) -> BackendResult<CleanupReport> {
        if let Some(report) = self.base.begin_destroy().await {
            return Ok(report);
        }

        let _ = self.kill_vm_process().await;
        if self.qemu_config.serial_fallback {
            let sandbox_id = self.base.sandbox_id().await;
            let path = self.qemu_config.serial_socket_path(&sandbox_id);
            let _ = tokio::fs::remove_file(&path).await;
        }
        {
            let mut addr = self.guest_agent_addr.lock().await;
            *addr = None;
        }
        {
            let mut addr = self.qmp_addr.lock().await;
            *addr = None;
        }

        self.base.finish_destroy(vec![]).await
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
        tracing::info!("Suspending QEMU VM via QMP");

        if self.qemu_config.qmp_enabled {
            self.send_qmp_command("stop")
                .await
                .map_err(|err| BackendError::Failed {
                    operation: BackendOperation::Suspend,
                    message: format!("QMP stop failed: {err}"),
                })?;
        }

        {
            let mut state = self.base.state.lock().await;
            *state = SandboxState::Suspended;
        }
        Ok(())
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
        tracing::info!("Resuming QEMU VM via QMP");

        if self.qemu_config.qmp_enabled {
            self.send_qmp_command("cont")
                .await
                .map_err(|err| BackendError::Failed {
                    operation: BackendOperation::Resume,
                    message: format!("QMP cont failed: {err}"),
                })?;
        }

        {
            let mut state = self.base.state.lock().await;
            *state = SandboxState::Running;
        }
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
        tracing::info!("Forwarding exec to QEMU guest-agent");
        let state = self.base.current_state().await?;
        if state != SandboxState::Running {
            return Err(BackendError::InvalidState {
                operation: BackendOperation::Exec,
                expected: vec![SandboxState::Running],
                actual: state,
            });
        }
        // Direct adapter exec is not supported: guest sessions are owned by
        // sandboxd over the attached vsock or Unix transport. Callers must go
        // through the supervisor handshake instead of dialing the guest
        // directly.
        Err(BackendError::Failed {
            operation: BackendOperation::Exec,
            message: "direct adapter exec is not supported; use the sandboxd guest session".into(),
        })
    }

    async fn stats(&self) -> BackendResult<BackendStats> {
        self.base.build_stats("QEMU", None).await
    }

    async fn health(&self) -> BackendResult<BackendHealth> {
        let state = self.base.current_state().await?;
        if matches!(state, SandboxState::Running) {
            return Ok(BackendHealth {
                status: BackendHealthStatus::Ready,
                checked_at: pico_core::now_iso(),
                message: None,
            });
        }
        self.base.build_health("QEMU VM").await
    }

    async fn diagnostics(&self) -> BackendResult<DiagnosticBundle> {
        let sandbox_id = self.base.sandbox_id().await;
        let state = self.base.current_state().await?;
        let boot_latency = *self.base.boot_latency_ms.lock().await;
        let mut summary = format!("QEMU backend state: {state}");
        if let Some(latency) = boot_latency {
            summary.push_str(&format!(", boot_latency_ms={latency}"));
        }
        Ok(DiagnosticBundle {
            captured_at: pico_core::now_iso(),
            summary,
            artifacts: vec![
                self.stdout_log_path(&sandbox_id).display().to_string(),
                self.stderr_log_path(&sandbox_id).display().to_string(),
            ],
        })
    }

    async fn port_addr(&self, guest_port: u16) -> BackendResult<Option<SocketAddr>> {
        let state = self.base.current_state().await?;
        if state == SandboxState::Running {
            let guest_agent_addr = *self.guest_agent_addr.lock().await;
            Ok(guest_agent_addr.map(|addr| SocketAddr::new(addr.ip(), guest_port)))
        } else {
            Ok(None)
        }
    }

    fn port_exposure(&self, guest_port: u16) -> PortExposure {
        if guest_port == 22 {
            PortExposure::BackendManaged
        } else {
            PortExposure::HostProxy
        }
    }
}

fn default_log_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("PICO_QEMU_LOG_DIR") {
        return PathBuf::from(dir);
    }

    let home = std::env::var_os("HOME").unwrap_or_else(|| "/tmp".into());
    PathBuf::from(home).join(".local/share/pico/logs/qemu")
}

impl QemuAdapter {}

fn allocate_guest_agent_addr(configured: SocketAddr) -> Result<SocketAddr> {
    let listener = std::net::TcpListener::bind((configured.ip(), 0))?;
    let addr = listener.local_addr()?;
    drop(listener);
    Ok(addr)
}

fn enrich_with_qemu_logs(
    err: SandboxError,
    exit_status: Option<&std::process::ExitStatus>,
    stdout_log_path: &Path,
    stderr_log_path: &Path,
) -> SandboxError {
    let mut details = Vec::new();
    if let Some(status) = exit_status {
        details.push(format!("QEMU exit status: {status}"));
    }
    if let Some(tail) = tail_file(stdout_log_path, 80).filter(|tail| !tail.trim().is_empty()) {
        details.push(format!(
            "QEMU guest console {}: {}",
            stdout_log_path.display(),
            tail.trim()
        ));
    }
    if let Some(tail) = tail_file(stderr_log_path, 20).filter(|tail| !tail.trim().is_empty()) {
        details.push(format!(
            "QEMU stderr {}: {}",
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

fn apply_qemu_hardening(hardening: &crate::RuntimeHardening) -> Result<()> {
    if !hardening.is_enabled() {
        return Ok(());
    }

    tracing::info!(
        isolate_namespaces = hardening.isolate_namespaces,
        unshare_mount = hardening.unshare_mount_namespace,
        "applying QEMU runtime hardening"
    );

    if hardening.isolate_namespaces {
        pico_runtime_hardening::apply_standard_isolation(hardening.unshare_mount_namespace)
            .map_err(|err| SandboxError::Other(format!("namespace isolation failed: {err}")))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qemu::config::GUEST_AGENT_VSOCK_PORT;

    #[tokio::test]
    async fn boot_requires_prepare_without_changing_state() {
        let adapter = QemuAdapter::new();

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
        let adapter = QemuAdapter::new();

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
        let adapter = QemuAdapter::new();

        let first = adapter.destroy().await.unwrap();
        assert!(first.released.is_empty());

        let second = adapter.destroy().await.unwrap();
        assert!(second.released.is_empty());

        assert_eq!(adapter.state().await.unwrap(), SandboxState::Destroyed);
    }

    #[tokio::test]
    async fn destroy_transitions_to_destroyed_state() {
        let adapter = QemuAdapter::new();

        adapter.destroy().await.unwrap();

        assert_eq!(adapter.state().await.unwrap(), SandboxState::Destroyed);
    }

    #[tokio::test]
    async fn cleanup_delegates_to_destroy() {
        let adapter = QemuAdapter::new();

        let report = adapter.cleanup().await.unwrap();

        assert_eq!(adapter.state().await.unwrap(), SandboxState::Destroyed);
        assert!(report.released.is_empty());
        assert!(report.remaining.is_empty());
    }

    #[tokio::test]
    async fn attach_transport_requires_running_state() {
        let adapter = QemuAdapter::new();

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

    async fn running_adapter_with(config: QemuConfig) -> QemuAdapter {
        let adapter = QemuAdapter::with_config(config);
        adapter
            .base
            .config
            .lock()
            .await
            .replace(sample_sandbox_config());
        *adapter.base.state.lock().await = SandboxState::Running;
        adapter
    }

    fn vsock_config() -> QemuConfig {
        let mut config = QemuConfig::detect_defaults();
        config.validate_paths = false;
        config.enable_vsock = true;
        config.serial_fallback = false;
        config
    }

    #[tokio::test]
    async fn attach_transport_returns_vsock_by_default_in_production() {
        let mut config = QemuConfig::detect_defaults();
        config.validate_paths = false;
        config.mode = QemuMode::Production;
        // Production enables vsock unless explicitly opted out.
        config.enable_vsock = true;
        config.serial_fallback = false;
        let adapter = running_adapter_with(config).await;

        let transport = adapter.attach_transport().await.unwrap();
        match transport {
            GuestTransport::Vsock {
                cid,
                port,
                uds_path,
            } => {
                assert!(cid >= 3);
                assert_eq!(port, GUEST_AGENT_VSOCK_PORT);
                assert_eq!(uds_path, None);
            }
            other => panic!("production QEMU attach must return Vsock, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn attach_transport_vsock_cid_is_stable_for_sandbox() {
        let adapter = running_adapter_with(vsock_config()).await;

        let first = adapter.attach_transport().await.unwrap();
        let second = adapter.attach_transport().await.unwrap();
        assert_eq!(first, second);
    }

    #[tokio::test]
    async fn attach_transport_fails_closed_when_vsock_and_serial_disabled() {
        let mut config = QemuConfig::detect_defaults();
        config.validate_paths = false;
        config.enable_vsock = false;
        config.serial_fallback = false;
        let addr: SocketAddr = "127.0.0.1:49152".parse().unwrap();
        config.guest_agent_addr = addr;
        let adapter = running_adapter_with(config).await;
        *adapter.guest_agent_addr.lock().await = Some(addr);

        // Neither vsock nor serial fallback means fail closed.
        let err = adapter.attach_transport().await.unwrap_err();
        assert!(matches!(err, BackendError::IncompleteSetup { .. }));
    }

    #[tokio::test]
    async fn attach_transport_returns_unix_for_serial_fallback() {
        let mut config = QemuConfig::detect_defaults();
        config.validate_paths = false;
        config.enable_vsock = false;
        config.serial_fallback = true;
        let adapter = running_adapter_with(config).await;

        let transport = adapter.attach_transport().await.unwrap();
        match transport {
            GuestTransport::Unix { path } => {
                assert!(path.ends_with("sbx_qemu_test.serial.sock"));
            }
            other => panic!("expected serial Unix transport, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn wait_ready_accepts_vsock_and_unix_transports() {
        let adapter = running_adapter_with(vsock_config()).await;

        let vsock = GuestTransport::Vsock {
            cid: 5,
            port: GUEST_AGENT_VSOCK_PORT,
            uds_path: None,
        };
        adapter.wait_ready(&vsock).await.unwrap();
        assert_eq!(adapter.state().await.unwrap(), SandboxState::Running);

        let unix = GuestTransport::Unix {
            path: "/tmp/pico-qemu-test.serial.sock".into(),
        };
        adapter.wait_ready(&unix).await.unwrap();
        assert_eq!(adapter.state().await.unwrap(), SandboxState::Running);
    }

    async fn running_adapter() -> QemuAdapter {
        let mut config = QemuConfig::detect_defaults();
        config.validate_paths = false;
        config.qmp_enabled = false;
        config.enable_vsock = true;
        config.serial_fallback = false;
        let adapter = QemuAdapter::with_config(config);
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
            id: "sbx_qemu_test".into(),
            network_isolated: true,
            ..Default::default()
        }
    }

    #[test]
    fn metadata_advertises_expected_capabilities() {
        let metadata = QemuAdapter::new().metadata();

        assert_eq!(metadata.runtime, pico_core::RuntimeType::Qemu);
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
        assert!(
            metadata
                .capabilities
                .contains(BackendCapability::BackendManagedPortForwarding)
        );
        assert!(!metadata.capabilities.contains(BackendCapability::Fork));
    }

    #[tokio::test]
    async fn exec_fails_closed_without_sandboxd_session() {
        // Direct adapter exec is not supported: guest sessions are owned by
        // sandboxd over the attached vsock or Unix transport.
        let adapter = running_adapter().await;

        let err = adapter
            .exec(exec_req("printf", &["pico-qemu"]))
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

    /// Serves one minimal QMP session (greeting, capabilities, one command)
    /// on an already-bound listener, then returns.
    async fn serve_one_qmp_session(listener: tokio::net::TcpListener) {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
        let (stream, _) = listener.accept().await.unwrap();
        let (reader, mut writer) = tokio::io::split(stream);
        let mut lines = tokio::io::BufReader::new(reader).lines();
        writer
            .write_all(b"{\"QMP\":{\"version\":{\"qemu\":{\"major\":8}}}}\n")
            .await
            .unwrap();
        // qmp_capabilities
        assert!(lines.next_line().await.unwrap().is_some());
        writer.write_all(b"{}\n").await.unwrap();
        // stop/cont
        assert!(lines.next_line().await.unwrap().is_some());
        writer.write_all(b"{\"return\":{}}\n").await.unwrap();
    }

    /// Regression test: the QMP listener opens after QEMU's main loop is up,
    /// which lags spawn. `suspend` must wait for a late listener instead of
    /// failing on the first refused dial (live-boot walk dialed 4ms post-spawn).
    #[tokio::test]
    async fn suspend_waits_for_late_qmp_listener() {
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);
        // The fake server binds the same port after a delay, mimicking QEMU
        // opening QMP post-spawn. SO_REUSEADDR is not set on either side, so
        // a different process grabbing the port first would fail this test
        // loudly instead of passing spuriously.
        let server = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
            serve_one_qmp_session(listener).await;
        });

        let mut config = QemuConfig::detect_defaults();
        config.qmp_enabled = true;
        let adapter = QemuAdapter::with_config(config);
        *adapter.base.state.lock().await = SandboxState::Running;
        *adapter.qmp_addr.lock().await = Some(addr);

        adapter.suspend().await.unwrap();
        assert_eq!(adapter.state().await.unwrap(), SandboxState::Suspended);
        tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .expect("fake QMP server must complete")
            .unwrap();
    }

    /// The dial retry must fail fast when the VM process is already gone
    /// instead of burning the whole deadline against a dead port.
    #[tokio::test]
    async fn suspend_fails_fast_when_vm_exited() {
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);

        let mut dead = tokio::process::Command::new("true").spawn().unwrap();
        let status = dead.wait().await.unwrap();
        assert!(status.success());

        let mut config = QemuConfig::detect_defaults();
        config.qmp_enabled = true;
        let adapter = QemuAdapter::with_config(config);
        *adapter.base.state.lock().await = SandboxState::Running;
        *adapter.qmp_addr.lock().await = Some(addr);
        *adapter.vm_process.lock().await = Some(dead);

        let err = adapter.suspend().await.unwrap_err().to_string();
        assert!(
            err.contains("QEMU exited"),
            "dead VM must fail fast with exit status, got: {err}"
        );
    }

    #[tokio::test]
    async fn fork_returns_unsupported() {
        let adapter = QemuAdapter::new();

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
    fn port_exposure_returns_backend_managed_for_ssh() {
        let adapter = QemuAdapter::new();

        let exposure = adapter.port_exposure(22);
        assert_eq!(exposure, PortExposure::BackendManaged);
    }

    #[test]
    fn port_exposure_returns_host_proxy_for_non_ssh() {
        let adapter = QemuAdapter::new();

        let exposure = adapter.port_exposure(80);
        assert_eq!(exposure, PortExposure::HostProxy);
    }

    #[test]
    fn ssh_username_returns_root() {
        let adapter = QemuAdapter::new();
        assert_eq!(adapter.ssh_username(), "root");
    }

    #[test]
    fn ssh_home_dir_returns_root() {
        let adapter = QemuAdapter::new();
        assert_eq!(adapter.ssh_home_dir(), "/root");
    }

    #[tokio::test]
    async fn stats_returns_state_and_boot_latency() {
        let adapter = QemuAdapter::new();

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
        let adapter = QemuAdapter::new();
        *adapter.base.state.lock().await = SandboxState::Failed;

        let health = adapter.health().await.unwrap();

        assert_eq!(health.status, BackendHealthStatus::Degraded);
        assert!(health.message.is_some_and(|m| m.contains("failed")));
    }

    #[tokio::test]
    async fn health_reports_unavailable_when_destroyed() {
        let adapter = QemuAdapter::new();
        *adapter.base.state.lock().await = SandboxState::Destroyed;

        let health = adapter.health().await.unwrap();

        assert_eq!(health.status, BackendHealthStatus::Unavailable);
        assert!(health.message.is_some_and(|m| m.contains("destroyed")));
    }

    #[tokio::test]
    async fn health_reports_ready_when_pending() {
        let adapter = QemuAdapter::new();

        let health = adapter.health().await.unwrap();

        assert_eq!(health.status, BackendHealthStatus::Ready);
    }

    #[tokio::test]
    async fn diagnostics_includes_log_artifacts() {
        let adapter = QemuAdapter::new();

        let bundle = adapter.diagnostics().await.unwrap();

        assert!(bundle.summary.contains("QEMU backend state"));
        assert_eq!(bundle.artifacts.len(), 2);
        assert!(bundle.artifacts.iter().any(|a| a.contains("stdout.log")));
        assert!(bundle.artifacts.iter().any(|a| a.contains("stderr.log")));
    }

    #[tokio::test]
    async fn port_addr_returns_none_when_not_running() {
        let adapter = QemuAdapter::new();

        let addr = adapter.port_addr(8080).await.unwrap();

        assert!(addr.is_none());
    }

    #[tokio::test]
    async fn prepare_sets_state_to_preparing() {
        let mut config = QemuConfig::detect_defaults();
        config.validate_paths = false;
        let adapter = QemuAdapter::with_config(config);

        let _ = adapter.prepare(&sample_sandbox_config()).await.unwrap();

        assert_eq!(adapter.state().await.unwrap(), SandboxState::Preparing);
    }

    #[tokio::test]
    async fn suspend_and_resume_are_noop_when_qmp_disabled() {
        let mut config = QemuConfig::detect_defaults();
        config.qmp_enabled = false;
        let adapter = QemuAdapter::with_config(config);
        *adapter.base.state.lock().await = SandboxState::Running;

        adapter.suspend().await.unwrap();
        assert_eq!(adapter.state().await.unwrap(), SandboxState::Suspended);

        adapter.resume().await.unwrap();
        assert_eq!(adapter.state().await.unwrap(), SandboxState::Running);
    }

    #[tokio::test]
    async fn suspend_of_suspended_is_idempotent() {
        let mut config = QemuConfig::detect_defaults();
        config.qmp_enabled = false;
        let adapter = QemuAdapter::with_config(config);
        *adapter.base.state.lock().await = SandboxState::Suspended;

        adapter.suspend().await.unwrap();
        assert_eq!(adapter.state().await.unwrap(), SandboxState::Suspended);
    }

    #[tokio::test]
    async fn resume_of_running_is_idempotent() {
        let mut config = QemuConfig::detect_defaults();
        config.qmp_enabled = false;
        let adapter = QemuAdapter::with_config(config);
        *adapter.base.state.lock().await = SandboxState::Running;

        adapter.resume().await.unwrap();
        assert_eq!(adapter.state().await.unwrap(), SandboxState::Running);
    }

    #[test]
    fn allocate_guest_agent_addr_uses_available_port_for_zero_port_config() {
        let addr = allocate_guest_agent_addr("127.0.0.1:0".parse().unwrap()).unwrap();
        assert_ne!(addr.port(), 0);
    }

    #[test]
    fn allocate_guest_agent_addr_uses_configured_ip_and_assigns_port() {
        let addr = allocate_guest_agent_addr("127.0.0.1:9999".parse().unwrap()).unwrap();
        assert_eq!(addr.ip(), std::net::IpAddr::from([127, 0, 0, 1]));
        assert_ne!(addr.port(), 9999);
    }

    #[test]
    fn enrich_with_qemu_logs_appends_exit_status() {
        let err = SandboxError::Other("boot failed".into());
        let dir = tempfile::tempdir().unwrap();
        let stdout = dir.path().join("stdout.log");
        let stderr = dir.path().join("stderr.log");
        std::fs::write(&stdout, "guest console output").unwrap();
        std::fs::write(&stderr, "").unwrap();

        let enriched = enrich_with_qemu_logs(err, None, &stdout, &stderr);

        let msg = enriched.to_string();
        assert!(msg.contains("guest console"));
    }

    #[tokio::test]
    async fn prepare_returns_resource_receipts() {
        let mut config = QemuConfig::detect_defaults();
        config.validate_paths = false;
        let adapter = QemuAdapter::with_config(config);

        let prepared = adapter.prepare(&sample_sandbox_config()).await.unwrap();

        assert!(!prepared.resources.is_empty());
        assert!(prepared.resources.iter().any(|r| r.class == "vm-process"));
    }

    #[tokio::test]
    async fn prepare_rejects_missing_kernel_when_validate_paths_enabled() {
        let mut config = QemuConfig::detect_defaults();
        config.validate_paths = true;
        config.kernel.image_path = PathBuf::from("/tmp/pico-missing-vmlinux-for-test");
        let adapter = QemuAdapter::with_config(config);

        let error = adapter.prepare(&sample_sandbox_config()).await.unwrap_err();

        assert!(matches!(error, BackendError::Failed { .. }));
    }

    #[tokio::test]
    async fn conformance_capability_declarations_match_qemu_lifecycle() {
        let mut config = QemuConfig::detect_defaults();
        config.validate_paths = false;
        let adapter = QemuAdapter::with_config(config);
        let metadata = adapter.metadata();

        // QEMU advertises the broadest capability set among production backends
        // including BackendManagedPortForwarding.
        assert!(metadata.capabilities.contains(BackendCapability::Boot));
        assert!(
            metadata
                .capabilities
                .contains(BackendCapability::GuestTransport)
        );
        assert!(
            metadata
                .capabilities
                .contains(BackendCapability::GuestReadiness)
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
        assert!(
            metadata
                .capabilities
                .contains(BackendCapability::BackendManagedPortForwarding)
        );

        // QEMU does not support Fork. Must be explicitly absent.
        assert!(!metadata.capabilities.contains(BackendCapability::Fork));

        // Fork returns Unsupported.
        let fork_err = adapter
            .fork(&SandboxConfig {
                id: "sbx_qemu_fork".into(),
                network_isolated: true,
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert!(matches!(fork_err, BackendError::Unsupported { .. }));

        // BackendManagedPortForwarding is declared: port 22 must be BackendManaged.
        assert_eq!(adapter.port_exposure(22), PortExposure::BackendManaged);
        // Non-SSH port is HostProxy.
        assert_eq!(adapter.port_exposure(8080), PortExposure::HostProxy);
    }
}

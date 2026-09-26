//! Host-process supervision for `sandboxd`.
//!
//! This module owns process spawning, pidfd acquisition on Linux, bounded
//! stdout and stderr capture, cancellation, absolute deadline enforcement, and
//! process-tree cleanup. Stream contents never enter the durable ledger.

use hashbrown::HashMap;
use std::ffi::OsString;
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::ledger::{Ledger, ProcessIdentityRecord};
use crate::resources::HostResourceManager;
use crate::supervisor::{
    CommandContext, OperationKind, OperationOutcome, OutcomeReason, OutcomeStatus, SupervisorError,
    base_outcome, duration_until,
};

const MAX_CAPTURE_BYTES: usize = 1024 * 1024;

/// Request for a directly supervised host process.
#[derive(Debug, Clone)]
pub struct ProcessRequest {
    /// Executable path or name. No shell is invoked.
    pub program: OsString,
    /// Arguments passed directly to the executable.
    pub args: Vec<OsString>,
    /// Optional working directory.
    pub current_dir: Option<PathBuf>,
    /// Optional stdin bytes. These bytes are never persisted.
    pub stdin: Vec<u8>,
}

impl ProcessRequest {
    /// Creates a request for an executable without arguments.
    #[must_use]
    pub fn new(program: impl Into<OsString>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            current_dir: None,
            stdin: Vec::new(),
        }
    }

    /// Validates request invariants before any process is spawned.
    pub(crate) fn validate(&self) -> Result<(), SupervisorError> {
        if self.program.is_empty() {
            Err(SupervisorError::InvalidProcessRequest(
                "program must not be empty".into(),
            ))
        } else {
            Ok(())
        }
    }
}

/// Output from a supervised host process.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessOutput {
    /// Durable operation outcome.
    pub outcome: OperationOutcome,
    /// Process exit code when one was reported.
    pub exit_code: Option<i32>,
    /// Bounded stdout bytes. These bytes are never persisted.
    pub stdout: Vec<u8>,
    /// Bounded stderr bytes. These bytes are never persisted.
    pub stderr: Vec<u8>,
}

#[derive(Clone)]
pub(crate) struct ProcessRegistry {
    active: Arc<Mutex<HashMap<String, ProcessHandle>>>,
    host_resources: HostResourceManager,
}

struct ProcessHandle {
    pidfd: Option<OwnedFd>,
    stream_count: usize,
}

impl ProcessRegistry {
    /// Creates an empty registry for supervised host processes.
    pub(crate) fn new(host_resources: HostResourceManager) -> Self {
        Self {
            active: Arc::new(Mutex::new(HashMap::new())),
            host_resources,
        }
    }

    /// Returns the number of live process handles.
    pub(crate) async fn active_count(&self) -> usize {
        self.active.lock().await.len()
    }

    /// Returns the number of live stdin, stdout, and stderr handles.
    pub(crate) async fn active_stream_count(&self) -> usize {
        self.active
            .lock()
            .await
            .values()
            .map(|handle| handle.stream_count)
            .sum()
    }

    /// Returns the number of Linux pidfds currently owned by the registry.
    pub(crate) async fn active_pidfd_count(&self) -> usize {
        self.active
            .lock()
            .await
            .values()
            .filter(|handle| handle.pidfd.is_some())
            .count()
    }

    /// Runs one host process under durable `sandboxd` supervision.
    ///
    /// The process identity is recorded before the registry takes ownership of
    /// the live handles so restart reconciliation can explain what was running
    /// even if the supervisor exits mid-operation.
    pub(crate) async fn run(
        &self,
        ledger: &Ledger,
        context: &CommandContext,
        host_boot_id: &str,
        request: ProcessRequest,
        token: CancellationToken,
    ) -> Result<ProcessOutput, SupervisorError> {
        let mut command = Command::new(&request.program);
        command
            .args(&request.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if let Some(current_dir) = request.current_dir.as_ref() {
            command.current_dir(current_dir);
        }
        #[cfg(unix)]
        command.process_group(0);

        let mut child = command.spawn()?;
        let pid = child.id().ok_or_else(|| {
            SupervisorError::InvalidProcessRequest("spawned process did not expose a pid".into())
        })?;
        let identity = inspect_process(pid, &request.program, host_boot_id);
        self.host_resources
            .attach_process(context.sandbox_id.as_str(), pid);
        let pidfd = open_pidfd(pid);
        let pidfd_available = pidfd.is_some();

        let mut stdin = child.stdin.take();
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        ledger
            .record_process(ProcessIdentityRecord {
                operation_id: &context.operation_id,
                sandbox_id: &context.sandbox_id,
                pid,
                process_start_ticks: identity.process_start_ticks,
                host_boot_id: &identity.host_boot_id,
                executable: &identity.executable,
                cgroup_identity: identity.cgroup_identity.as_deref(),
                pidfd_available,
            })
            .await?;
        let stream_count = usize::from(stdin.is_some())
            + usize::from(stdout.is_some())
            + usize::from(stderr.is_some());
        self.active.lock().await.insert(
            context.operation_id.as_str().to_string(),
            ProcessHandle {
                pidfd,
                stream_count,
            },
        );

        let stdin_bytes = request.stdin;
        let stdin_task = tokio::spawn(async move {
            if let Some(mut stdin) = stdin.take() {
                if !stdin_bytes.is_empty() {
                    stdin.write_all(&stdin_bytes).await?;
                }
                stdin.shutdown().await?;
            }
            Ok::<(), std::io::Error>(())
        });
        let stdout_task = tokio::spawn(read_bounded(stdout));
        let stderr_task = tokio::spawn(read_bounded(stderr));

        let timeout = duration_until(context.deadline_unix_ms);
        let termination = tokio::select! {
            biased;
            () = token.cancelled() => {
                kill_process_tree(pid, &mut child).await;
                ProcessTermination::Canceled
            }
            () = tokio::time::sleep(timeout) => {
                kill_process_tree(pid, &mut child).await;
                ProcessTermination::TimedOut
            }
            status = child.wait() => match status {
                Ok(status) => ProcessTermination::Exited(status),
                Err(error) => ProcessTermination::WaitFailed(error),
            },
        };
        if matches!(termination, ProcessTermination::Exited(_)) {
            kill_process_group(pid);
        }

        let _ = stdin_task.await;
        let stdout = join_stream(stdout_task).await;
        let stderr = join_stream(stderr_task).await;
        let handle = self
            .active
            .lock()
            .await
            .remove(context.operation_id.as_str());
        debug_assert!(
            handle
                .as_ref()
                .is_none_or(|handle| handle.stream_count <= 3)
        );

        let (outcome, exit_code, process_state) = match termination {
            ProcessTermination::Exited(status) => {
                let reason = if status.code().is_some() {
                    OutcomeReason::ProcessExited
                } else {
                    OutcomeReason::ProcessSignaled
                };
                (
                    OperationOutcome {
                        status: if status.success() {
                            OutcomeStatus::Succeeded
                        } else {
                            OutcomeStatus::Failed
                        },
                        reason,
                        message: (!status.success())
                            .then(|| format!("process exited with {status}")),
                        ..base_outcome(context, OperationKind::Process)
                    },
                    status.code(),
                    "exited",
                )
            }
            ProcessTermination::Canceled => (
                OperationOutcome {
                    status: OutcomeStatus::Canceled,
                    reason: OutcomeReason::CanceledByHost,
                    message: Some("process canceled by host-agent".into()),
                    ..base_outcome(context, OperationKind::Process)
                },
                None,
                "canceled",
            ),
            ProcessTermination::TimedOut => (
                OperationOutcome {
                    status: OutcomeStatus::TimedOut,
                    reason: OutcomeReason::DeadlineExceeded,
                    message: Some("process deadline elapsed".into()),
                    ..base_outcome(context, OperationKind::Process)
                },
                None,
                "timed_out",
            ),
            ProcessTermination::WaitFailed(error) => (
                OperationOutcome {
                    status: OutcomeStatus::Failed,
                    reason: OutcomeReason::ProcessFailure,
                    message: Some(format!("failed to wait for process: {error}")),
                    ..base_outcome(context, OperationKind::Process)
                },
                None,
                "failed",
            ),
        };
        ledger
            .complete_process(&context.operation_id, process_state)
            .await?;
        Ok(ProcessOutput {
            outcome,
            exit_code,
            stdout,
            stderr,
        })
    }
}

struct ProcessIdentity {
    process_start_ticks: Option<u64>,
    host_boot_id: String,
    executable: String,
    cgroup_identity: Option<String>,
}

enum ProcessTermination {
    Exited(std::process::ExitStatus),
    Canceled,
    TimedOut,
    WaitFailed(std::io::Error),
}

async fn read_bounded<T>(stream: Option<T>) -> std::io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin,
{
    let Some(mut stream) = stream else {
        return Ok(Vec::new());
    };
    let mut output = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        let remaining = MAX_CAPTURE_BYTES.saturating_sub(output.len());
        output.extend_from_slice(&chunk[..read.min(remaining)]);
    }
    Ok(output)
}

/// Joins one stream reader and drops failures so teardown can continue.
async fn join_stream(task: tokio::task::JoinHandle<std::io::Result<Vec<u8>>>) -> Vec<u8> {
    task.await.ok().and_then(Result::ok).unwrap_or_default()
}

/// Kills the process group and waits for the direct child to exit.
async fn kill_process_tree(pid: u32, child: &mut tokio::process::Child) {
    kill_process_group(pid);
    let _ = child.kill().await;
    let _ = child.wait().await;
}

/// Sends `SIGKILL` to the spawned process group when the platform supports it.
fn kill_process_group(pid: u32) {
    #[cfg(unix)]
    {
        if let Ok(pid) = i32::try_from(pid) {
            // SAFETY: kill is called with a negative process group id created for this child.
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
        }
    }
}

/// Reconstructs the stable identity evidence needed for restart reconciliation.
fn inspect_process(_pid: u32, requested_program: &OsString, host_boot_id: &str) -> ProcessIdentity {
    #[cfg(target_os = "linux")]
    {
        let executable = std::fs::read_link(format!("/proc/{_pid}/exe"))
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_else(|_| requested_program.to_string_lossy().into_owned());

        let process_start_ticks = std::fs::read_to_string(format!("/proc/{_pid}/stat"))
            .ok()
            .and_then(|stat| parse_linux_start_ticks(&stat));

        let cgroup_identity = std::fs::read_to_string(format!("/proc/{_pid}/cgroup"))
            .ok()
            .map(|value| value.trim().to_string());

        ProcessIdentity {
            process_start_ticks,
            host_boot_id: host_boot_id.to_string(),
            executable,
            cgroup_identity,
        }
    }

    #[cfg(not(target_os = "linux"))]
    ProcessIdentity {
        process_start_ticks: None,
        host_boot_id: host_boot_id.to_string(),
        executable: requested_program.to_string_lossy().into_owned(),
        cgroup_identity: None,
    }
}

#[cfg(target_os = "linux")]
/// Extracts the Linux process start tick field from `/proc/<pid>/stat`.
fn parse_linux_start_ticks(stat: &str) -> Option<u64> {
    let close = stat.rfind(')')?;
    stat.get(close + 2..)?
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

#[cfg(target_os = "linux")]
/// Opens a pidfd for a live process when the running kernel supports it.
fn open_pidfd(pid: u32) -> Option<OwnedFd> {
    use std::os::fd::FromRawFd;

    let pid = libc::pid_t::try_from(pid).ok()?;
    // SAFETY: pidfd_open returns a new owned descriptor on success.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    let fd = i32::try_from(fd).ok()?;
    if fd < 0 {
        None
    } else {
        // SAFETY: fd was returned as a fresh descriptor by pidfd_open.
        Some(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

#[cfg(not(target_os = "linux"))]
/// Returns `None` on platforms that do not expose `pidfd_open`.
fn open_pidfd(_pid: u32) -> Option<OwnedFd> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::resources::HostResourceConfig;

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_stat_parser_reads_start_ticks_after_parenthesized_name() {
        let stat = "42 (process name) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 98765 21";
        assert_eq!(parse_linux_start_ticks(stat), Some(98765));
    }

    #[tokio::test]
    async fn empty_registry_reports_no_active_handles() {
        let host = HostResourceManager::new(HostResourceConfig::new(std::env::temp_dir()));
        let registry = ProcessRegistry::new(host);
        assert_eq!(registry.active_count().await, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pidfd_open_tracks_live_process_when_kernel_supports_it() {
        let pidfd = open_pidfd(std::process::id());
        assert!(pidfd.is_some());
    }
}

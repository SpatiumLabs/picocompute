//! In-process stub agent used for local smoke tests without a VM backend.
//!
//! `StubAgent` is **not** on the production host-resource ownership path.
//! It may create or delete workspace directories for local file/task smoke
//! tests only. Production lifecycle materialization of workspace, cgroup, and
//! CPU pinning is owned exclusively by `sandboxd`'s `HostResourceManager`.
//! Do not copy stub ensure/delete patterns into `HostAgent`.

use async_trait::async_trait;
use hashbrown::HashMap;
use pico_core::{
    ExecRequest, ExecResponse, FileInfo, FileReadResponse, FileWriteRequest, Result, SandboxError,
    SandboxInfo, SandboxSpec, SandboxState, SshInfo, TaskEvent, TaskInfo, TaskRequest, TaskState,
    ensure_destroy_precondition, ensure_purge_precondition, ensure_stop_precondition, new_ulid,
    now_iso,
};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, broadcast};

use crate::health::HostHealth;
use crate::identity::{HostCapacity, HostIdentity, HostInventory};

pub struct StubAgent {
    sandboxes: Arc<Mutex<HashMap<String, SandboxInfo>>>,
    workspaces: crate::workspace::WorkspaceManager,
    task_registry: Arc<crate::task_registry::TaskRegistry>,
    public_host: Option<String>,
}

impl StubAgent {
    pub fn new(workspace_root: PathBuf) -> Result<Self> {
        Ok(Self {
            sandboxes: Arc::new(Mutex::new(HashMap::new())),
            workspaces: crate::workspace::WorkspaceManager::new(workspace_root)?,
            task_registry: Arc::new(crate::task_registry::TaskRegistry::new(64)),
            public_host: None,
        })
    }

    pub fn with_public_host(workspace_root: PathBuf, public_host: Option<String>) -> Result<Self> {
        Ok(Self {
            sandboxes: Arc::new(Mutex::new(HashMap::new())),
            workspaces: crate::workspace::WorkspaceManager::new(workspace_root)?,
            task_registry: Arc::new(crate::task_registry::TaskRegistry::new(64)),
            public_host,
        })
    }

    async fn run_task(
        self: Arc<Self>,
        sandbox_id: String,
        task_id: String,
        req: TaskRequest,
    ) -> Result<()> {
        let entry = self
            .task_registry
            .get(&task_id)
            .ok_or_else(|| SandboxError::TaskNotFound(task_id.clone()))?;
        let workspace = self.workspaces.sandbox_dir(&sandbox_id)?;

        {
            let mut info = entry.info.lock().await;
            info.state = TaskState::Running;
            info.started_at = Some(now_iso());
        }
        let _ = entry.events.send(TaskEvent::Status {
            ts: now_iso(),
            state: TaskState::Running,
        });

        let mut cmd = tokio::process::Command::new(&req.agent);
        cmd.arg(&req.prompt)
            .current_dir(&workspace)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = match cmd.spawn() {
            Ok(child) => child,
            Err(err) => {
                fail_task(&entry, format!("spawn failed: {err}")).await;
                return Ok(());
            }
        };

        let stdout_task = child.stdout.take().map(|stdout| {
            crate::stream_task_output(stdout, entry.events.clone(), crate::StreamKind::Stdout)
        });
        let stderr_task = child.stderr.take().map(|stderr| {
            crate::stream_task_output(stderr, entry.events.clone(), crate::StreamKind::Stderr)
        });

        let timeout = Duration::from_secs(req.timeout_secs.unwrap_or(600));
        let result = tokio::select! {
            () = entry.cancel.cancelled() => {
                let _ = child.kill().await;
                crate::TaskEnd::Cancelled
            }
            () = tokio::time::sleep(timeout) => {
                let _ = child.kill().await;
                crate::TaskEnd::Timeout
            }
            status = child.wait() => {
                match status {
                    Ok(status) => crate::TaskEnd::Exit(status.code().unwrap_or(-1)),
                    Err(err) => crate::TaskEnd::Error(err.to_string()),
                }
            }
        };

        let drain_output = matches!(result, crate::TaskEnd::Exit(_) | crate::TaskEnd::Error(_));
        if drain_output {
            if let Some(stdout_task) = stdout_task {
                let _ = stdout_task.await;
            }
            if let Some(stderr_task) = stderr_task {
                let _ = stderr_task.await;
            }
        }

        let (state, exit_code, error) = match result {
            crate::TaskEnd::Exit(0) => (TaskState::Completed, Some(0), None),
            crate::TaskEnd::Exit(code) => {
                (TaskState::Failed, Some(code), Some(format!("exit {code}")))
            }
            crate::TaskEnd::Cancelled => (TaskState::Cancelled, None, None),
            crate::TaskEnd::Timeout => (TaskState::Failed, None, Some("timeout".into())),
            crate::TaskEnd::Error(err) => (TaskState::Failed, None, Some(err)),
        };

        {
            let mut info = entry.info.lock().await;
            info.state = state;
            info.ended_at = Some(now_iso());
            info.exit_code = exit_code;
            info.error = error.clone();
        }
        if let Some(message) = error {
            let _ = entry.events.send(TaskEvent::Error {
                ts: now_iso(),
                message,
            });
        }
        let _ = entry.events.send(TaskEvent::Status {
            ts: now_iso(),
            state,
        });
        if let Some(exit_code) = exit_code {
            let _ = entry.events.send(TaskEvent::Result {
                ts: now_iso(),
                exit_code,
            });
        }
        Ok(())
    }
}

#[async_trait]
impl pico_core::SandboxService for StubAgent {
    async fn create(&self, spec: SandboxSpec) -> Result<SandboxInfo> {
        let id = spec.id.clone().unwrap_or_else(|| new_ulid("sbx"));
        self.workspaces.ensure(&id)?;
        let info = SandboxInfo {
            id: id.clone(),
            state: SandboxState::Running,
            ports: spec.ports.unwrap_or_default(),
            container_id: Some("stub-vm".into()),
            created_at: now_iso(),
            last_activity_at: now_iso(),
            ssh_port: Some(22),
            ssh_public_key: Some("ssh-ed25519 stub-key".into()),
        };
        self.sandboxes
            .lock()
            .await
            .insert(info.id.clone(), info.clone());
        Ok(info)
    }

    async fn list(
        &self,
        limit: usize,
        cursor: Option<String>,
    ) -> Result<(Vec<SandboxInfo>, Option<String>)> {
        let sandboxes = self.sandboxes.lock().await;
        let mut ids: Vec<&String> = sandboxes.keys().collect();
        ids.sort();
        let start = match &cursor {
            Some(c) => ids
                .iter()
                .position(|id| id.as_str() > c.as_str())
                .unwrap_or(ids.len()),
            None => 0,
        };
        let end = (start + limit).min(ids.len());
        let items: Vec<SandboxInfo> = ids[start..end]
            .iter()
            .filter_map(|id| sandboxes.get(*id).cloned())
            .collect();
        let next = if end < ids.len() {
            items.last().map(|i| i.id.clone())
        } else {
            None
        };
        Ok((items, next))
    }

    async fn get(&self, id: &str) -> Result<SandboxInfo> {
        self.sandboxes
            .lock()
            .await
            .get(id)
            .cloned()
            .ok_or(SandboxError::SandboxNotFound(id.into()))
    }

    async fn destroy(&self, id: &str) -> Result<()> {
        {
            let mut sandboxes = self.sandboxes.lock().await;
            let info = sandboxes
                .get(id)
                .ok_or_else(|| SandboxError::SandboxNotFound(id.into()))?;
            ensure_destroy_precondition(info.state)?;
            sandboxes.remove(id);
        }
        for entry in self.task_registry.for_sandbox(id) {
            crate::cancel_task_entry(&entry).await;
        }
        Ok(())
    }

    async fn purge(&self, id: &str) -> Result<()> {
        let state = self
            .sandboxes
            .lock()
            .await
            .get(id)
            .map(|info| info.state)
            .ok_or_else(|| SandboxError::SandboxNotFound(id.into()))?;
        ensure_purge_precondition(state)?;
        self.destroy(id).await?;
        self.workspaces.delete(id)
    }

    async fn stop(&self, id: &str) -> Result<()> {
        let mut sandboxes = self.sandboxes.lock().await;
        let info = sandboxes
            .get_mut(id)
            .ok_or_else(|| SandboxError::SandboxNotFound(id.into()))?;
        ensure_stop_precondition(info.state)?;
        info.state = SandboxState::Stopped;
        Ok(())
    }

    async fn suspend(&self, id: &str) -> Result<()> {
        let mut sandboxes = self.sandboxes.lock().await;
        let info = sandboxes
            .get_mut(id)
            .ok_or_else(|| SandboxError::SandboxNotFound(id.into()))?;
        match info.state {
            SandboxState::Suspended => Ok(()),
            SandboxState::Running => {
                info.state = SandboxState::Suspended;
                Ok(())
            }
            state => Err(SandboxError::InvalidStateTransition(format!(
                "cannot suspend sandbox from state {state}"
            ))),
        }
    }

    async fn resume(&self, id: &str) -> Result<()> {
        let mut sandboxes = self.sandboxes.lock().await;
        let info = sandboxes
            .get_mut(id)
            .ok_or_else(|| SandboxError::SandboxNotFound(id.into()))?;
        match info.state {
            SandboxState::Running => Ok(()),
            SandboxState::Suspended => {
                info.state = SandboxState::Running;
                Ok(())
            }
            state => Err(SandboxError::InvalidStateTransition(format!(
                "cannot resume sandbox from state {state}"
            ))),
        }
    }

    async fn keepalive(&self, id: &str) -> Result<()> {
        self.sandboxes
            .lock()
            .await
            .get(id)
            .ok_or(SandboxError::SandboxNotFound(id.into()))?;
        Ok(())
    }

    async fn exec(&self, _id: &str, _r: ExecRequest) -> Result<ExecResponse> {
        Ok(ExecResponse {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
            duration_ms: 0,
        })
    }

    async fn file_read(&self, id: &str, path: &str) -> Result<FileReadResponse> {
        // Inline traversal guards: the check must dominate the filesystem
        // sinks in this function for static analysis to recognize it.
        if id.contains("..") {
            return Err(SandboxError::PathEscape(id.into()));
        }
        if path.contains("..") {
            return Err(SandboxError::PathEscape(path.into()));
        }
        let full = self.workspaces.resolve_existing(id, path)?;
        let content = tokio::fs::read_to_string(&full).await?;
        let meta = tokio::fs::metadata(&full).await?;
        Ok(FileReadResponse {
            path: path.into(),
            content,
            size: meta.len(),
            modified_at: now_iso(),
        })
    }
    async fn file_write(&self, id: &str, req: FileWriteRequest) -> Result<FileInfo> {
        // Inline traversal guards (see file_read).
        if id.contains("..") {
            return Err(SandboxError::PathEscape(id.into()));
        }
        if req.path.contains("..") {
            return Err(SandboxError::PathEscape(req.path.clone()));
        }
        let full = self.workspaces.resolve_for_write(id, &req.path)?;
        if let Some(parent) = full.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        if req.append {
            let mut options = tokio::fs::OpenOptions::new();
            options.append(true).create(true);
            let mut file = options.open(&full).await?;
            tokio::io::AsyncWriteExt::write_all(&mut file, req.content.as_bytes()).await?;
            tokio::io::AsyncWriteExt::flush(&mut file).await?;
        } else {
            tokio::fs::write(&full, req.content.as_bytes()).await?;
        }
        let meta = tokio::fs::metadata(&full).await?;
        Ok(FileInfo {
            path: req.path,
            size: meta.len(),
            is_dir: false,
            modified_at: now_iso(),
        })
    }
    async fn file_list(&self, id: &str, dir: &str, recursive: bool) -> Result<Vec<FileInfo>> {
        // Inline traversal guards (see file_read).
        if id.contains("..") {
            return Err(SandboxError::PathEscape(id.into()));
        }
        if dir.contains("..") {
            return Err(SandboxError::PathEscape(dir.into()));
        }
        let root = self.workspaces.resolve_existing(id, dir)?;
        let sandbox_root = self.workspaces.sandbox_dir(id)?;
        let mut out = Vec::new();
        let mut stack = vec![root];

        while let Some(current) = stack.pop() {
            let mut entries = tokio::fs::read_dir(&current).await?;
            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();
                // Never follow symlinks: a symlinked directory must be
                // listed, not descended into, or listing escapes the
                // workspace when recursive.
                let meta = tokio::fs::symlink_metadata(&path).await?;
                let file_type = meta.file_type();
                let is_symlink = file_type.is_symlink();
                let is_dir = meta.is_dir() && !is_symlink;
                let rel = path
                    .strip_prefix(&sandbox_root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .to_string();
                out.push(FileInfo {
                    path: rel,
                    size: meta.len(),
                    is_dir,
                    modified_at: now_iso(),
                });
                if recursive && is_dir {
                    stack.push(path);
                }
            }
        }

        out.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(out)
    }
    async fn task_start(&self, id: &str, req: TaskRequest) -> Result<TaskInfo> {
        self.get(id).await?;
        let entry = self.task_registry.create(id);
        let task_id = entry.info.lock().await.id.clone();
        let started = entry.info.lock().await.clone();
        let runner = Arc::new(Self {
            sandboxes: Arc::clone(&self.sandboxes),
            workspaces: self.workspaces.clone(),
            task_registry: Arc::clone(&self.task_registry),
            public_host: self.public_host.clone(),
        });
        let sandbox_id = id.to_string();
        let handle = tokio::spawn(async move {
            if let Err(err) = runner.run_task(sandbox_id, task_id, req).await {
                tracing::error!(error = %err, "stub task runner failed");
            }
        });
        *entry.handle.lock().await = Some(handle);
        Ok(started)
    }
    async fn task_get(&self, id: &str, task_id: &str) -> Result<TaskInfo> {
        let entry = task_entry_for_sandbox(&self.task_registry, id, task_id)?;
        Ok(entry.info.lock().await.clone())
    }
    async fn task_cancel(&self, id: &str, task_id: &str) -> Result<()> {
        let entry = task_entry_for_sandbox(&self.task_registry, id, task_id)?;
        let info = entry.info.lock().await;
        if info.state.is_terminal() {
            return Err(SandboxError::Conflict(format!(
                "task is already {}",
                info.state.as_str()
            )));
        }
        entry.cancel.cancel();
        Ok(())
    }
    fn task_subscribe(&self, id: &str, task_id: &str) -> Result<broadcast::Receiver<TaskEvent>> {
        let entry = task_entry_for_sandbox(&self.task_registry, id, task_id)?;
        Ok(entry.events.subscribe())
    }

    async fn ssh_info(&self, id: &str) -> Result<SshInfo> {
        let info = self.get(id).await?;
        let ssh_port = info.ssh_port.unwrap_or(22);
        let public_key = info
            .ssh_public_key
            .unwrap_or_else(|| "ssh-ed25519 stub-key".to_string());
        Ok(SshInfo {
            host: self
                .public_host
                .clone()
                .unwrap_or_else(|| "localhost".to_string()),
            port: ssh_port,
            username: "root".to_string(),
            private_key: None,
            public_key,
        })
    }
}

#[async_trait]
impl pico_core::SandboxFacade for StubAgent {
    async fn create(&self, spec: SandboxSpec) -> Result<SandboxInfo> {
        pico_core::SandboxService::create(self, spec).await
    }

    async fn list(
        &self,
        limit: usize,
        cursor: Option<String>,
    ) -> Result<(Vec<SandboxInfo>, Option<String>)> {
        pico_core::SandboxService::list(self, limit, cursor).await
    }

    async fn get(&self, id: &str) -> Result<SandboxInfo> {
        pico_core::SandboxService::get(self, id).await
    }

    async fn destroy(&self, id: &str) -> Result<()> {
        pico_core::SandboxService::destroy(self, id).await
    }

    async fn purge(&self, id: &str) -> Result<()> {
        pico_core::SandboxService::purge(self, id).await
    }

    async fn stop(&self, id: &str) -> Result<()> {
        pico_core::SandboxService::stop(self, id).await
    }

    async fn keepalive(&self, id: &str) -> Result<()> {
        pico_core::SandboxService::keepalive(self, id).await
    }

    async fn exec(&self, id: &str, req: ExecRequest) -> Result<ExecResponse> {
        pico_core::SandboxService::exec(self, id, req).await
    }

    async fn suspend(&self, id: &str) -> Result<()> {
        pico_core::SandboxService::suspend(self, id).await
    }

    async fn resume(&self, id: &str) -> Result<()> {
        pico_core::SandboxService::resume(self, id).await
    }
}

#[async_trait]
impl crate::HostControl for StubAgent {
    async fn health(&self) -> HostHealth {
        let count = self.sandboxes.try_lock().map(|g| g.len()).unwrap_or(0);
        HostHealth::ready(count, vec![])
    }

    async fn inventory(&self) -> HostInventory {
        let boot = HostCapacity {
            cpu_count: 1,
            memory_mb_total: 1024,
            memory_mb_available: 1024,
            disk_mb_total: 10240,
            disk_mb_available: 10240,
        };
        let count = self.sandboxes.try_lock().map(|g| g.len()).unwrap_or(0) as u64;
        let allocated = crate::scheduler_capacity::AllocatedResources {
            vcpus: 0,
            memory_mb: 0,
            sandbox_count: count,
        };
        HostInventory {
            identity: HostIdentity::new(
                "stub-host".into(),
                "stub-cell".into(),
                "stub-region".into(),
            ),
            capacity: boot.clone(),
            supported_backends: vec![],
            agent_version: env!("CARGO_PKG_VERSION").into(),
            scheduler_capacity: Some(crate::scheduler_capacity::scheduler_capacity(
                &boot, allocated,
            )),
            pressure: Some(crate::scheduler_capacity::scheduler_pressure(0, 0)),
            current_sandboxes: count,
        }
    }

    async fn stats(&self) -> serde_json::Value {
        let count = self.sandboxes.lock().await.len();
        let boot = HostCapacity {
            cpu_count: 1,
            memory_mb_total: 1024,
            memory_mb_available: 1024,
            disk_mb_total: 10240,
            disk_mb_available: 10240,
        };
        let allocated = crate::scheduler_capacity::AllocatedResources {
            vcpus: 0,
            memory_mb: 0,
            sandbox_count: count as u64,
        };
        let capacity = crate::scheduler_capacity::scheduler_capacity(&boot, allocated);
        let pressure = crate::scheduler_capacity::scheduler_pressure(0, 0);
        serde_json::json!({
            "sandbox_count": count,
            "capacity": capacity,
            "pressure": pressure,
        })
    }
}

fn task_entry_for_sandbox(
    registry: &crate::task_registry::TaskRegistry,
    sandbox_id: &str,
    task_id: &str,
) -> Result<Arc<crate::task_registry::TaskEntry>> {
    let entry = registry
        .get(task_id)
        .ok_or_else(|| SandboxError::TaskNotFound(task_id.to_string()))?;
    if entry.sandbox_id != sandbox_id {
        return Err(SandboxError::TaskNotFound(task_id.to_string()));
    }
    Ok(entry)
}

async fn fail_task(entry: &Arc<crate::task_registry::TaskEntry>, message: String) {
    {
        let mut info = entry.info.lock().await;
        info.state = TaskState::Failed;
        info.error = Some(message.clone());
        info.ended_at = Some(now_iso());
    }
    let _ = entry.events.send(TaskEvent::Error {
        ts: now_iso(),
        message,
    });
    let _ = entry.events.send(TaskEvent::Status {
        ts: now_iso(),
        state: TaskState::Failed,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use pico_core::SandboxService;

    fn stub() -> StubAgent {
        StubAgent::new(std::env::temp_dir().join(new_ulid("pico_stub_test"))).unwrap()
    }

    #[test]
    fn stub_implements_narrow_facade() {
        fn assert_facade<T: pico_core::SandboxFacade>() {}
        assert_facade::<StubAgent>();
    }

    #[tokio::test]
    async fn destroy_missing_sandbox_returns_not_found() {
        let agent = stub();
        let err = agent.destroy("sbx_missing").await.unwrap_err();
        assert!(matches!(err, SandboxError::SandboxNotFound(_)));
    }

    #[tokio::test]
    async fn purge_requires_stopped() {
        let agent = stub();
        let info = agent
            .create(SandboxSpec {
                runtime: None,
                id: Some("sbx_stub_purge".into()),
                ports: None,
                env: None,
                memory_mb: None,
                vcpus: None,
                idle_timeout_secs: None,
                ssh_public_key: None,
                ssh_key_type: None,
                image_id: None,
                image_digest: None,
                credential_request: None,
                service_class: None,
            })
            .await
            .unwrap();
        assert!(matches!(
            agent.purge(&info.id).await,
            Err(SandboxError::InvalidStateTransition(_))
        ));
        agent.stop(&info.id).await.unwrap();
        agent.purge(&info.id).await.unwrap();
        assert!(matches!(
            agent.get(&info.id).await,
            Err(SandboxError::SandboxNotFound(_))
        ));
    }
}

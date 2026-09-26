//! Binary-level restart acceptance tests (ADR-0011).
//!
//! These tests spawn real `sandboxd`, `pico-host-agent`, and
//! `pico-guest-agent` processes, drive them through their public
//! interfaces (HTTP for host-agent, framed TCP for guest-agent), and
//! verify restart-resilience by sending SIGKILL and restarting.
//!
//! Unlike the in-process tests, these exercise:
//! - Real binary lifecycle (process spawn, signal handling, exit)
//! - Socket file inheritance and rebind after daemon restart
//! - Real guest-agent handshake over TCP
//! - HTTP API surface of host-agent
//!
//! ## Requirements
//!
//! - Linux (UDS + SIGKILL semantics)
//! - Binaries built with:
//!   `cargo build -p pico-sandboxd --features mock-backend \
//!    -p pico-host-agent -p pico-guest-agent`
//! - No KVM/Firecracker needed (uses MockBackend via feature flag)
//!
//! ## Running
//!
//! ```sh
//! cargo build -p pico-sandboxd --features mock-backend \
//!             -p pico-host-agent -p pico-guest-agent
//! cargo nextest run -p pico-host-agent --test binary_restart_acceptance
//! ```

#![cfg(target_os = "linux")]

use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::Duration;

use serde_json::{Value, json};
use tempfile::TempDir;

const HOST_TOKEN: &str = "binary-test-host-token";
const SANDBOXD_TOKEN: &str = "binary-test-sandboxd-token";
const HOST_ID: &str = "binary-test-host";
const CELL_ID: &str = "binary-test-cell";
const TIMEOUT: Duration = Duration::from_secs(15);

// ---------------------------------------------------------------------------
// Binary discovery
// ---------------------------------------------------------------------------

fn target_bin_dir() -> PathBuf {
    // Respect custom target dirs set by CI or developers; otherwise derive
    // from the test binary location (target/{profile}/deps/ -> target/{profile}/).
    if let Ok(dir) = std::env::var("CARGO_TARGET_DIR") {
        // Check profile subdir via current exe's profile name when available.
        let exe = std::env::current_exe().expect("current_exe");
        let profile = exe
            .parent()
            .and_then(|p| p.parent())
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .unwrap_or("debug");
        let candidate = PathBuf::from(&dir).join(profile);
        if candidate.exists() {
            return candidate;
        }
        return PathBuf::from(dir);
    }
    if let Ok(dir) = std::env::var("CARGO_BUILD_TARGET_DIR") {
        return PathBuf::from(dir);
    }
    let exe = std::env::current_exe().expect("current_exe");
    // Integration test binaries live in target/{profile}/deps/; the actual
    // binaries are one level up in target/{profile}/.
    exe.parent()
        .expect("exe parent")
        .parent()
        .expect("deps parent")
        .to_path_buf()
}

fn sandboxd_bin() -> PathBuf {
    target_bin_dir().join("sandboxd")
}

fn host_agent_bin() -> PathBuf {
    target_bin_dir().join("pico-host-agent")
}

fn guest_agent_bin() -> PathBuf {
    target_bin_dir().join("pico-guest-agent")
}

fn require_binaries() {
    let missing: Vec<String> = [sandboxd_bin(), host_agent_bin(), guest_agent_bin()]
        .iter()
        .filter(|p| !p.exists())
        .map(|p| p.display().to_string())
        .collect();
    if !missing.is_empty() {
        panic!(
            "Required binaries not found: {:?}. \
             Build with: cargo build -p pico-sandboxd --features mock-backend \
             -p pico-host-agent -p pico-guest-agent",
            missing
        );
    }
}

// ---------------------------------------------------------------------------
// Port allocation
// ---------------------------------------------------------------------------

fn free_port() -> u16 {
    TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .expect("bind free port")
        .local_addr()
        .expect("local_addr")
        .port()
}

// ---------------------------------------------------------------------------
// Process management
// ---------------------------------------------------------------------------

struct ProcessGuard {
    child: Option<Child>,
    name: &'static str,
    log_path: Option<PathBuf>,
}

impl ProcessGuard {
    fn spawn(name: &'static str, cmd: &mut Command, log_dir: &Path) -> Self {
        let log_path = log_dir.join(format!("{name}.log"));
        let log_file = std::fs::File::create(&log_path)
            .unwrap_or_else(|e| panic!("create log file for {name}: {e}"));
        let child = cmd
            .stdout(log_file.try_clone().expect("clone log file"))
            .stderr(log_file)
            .spawn()
            .unwrap_or_else(|e| panic!("failed to spawn {name}: {e}"));
        Self {
            child: Some(child),
            name,
            log_path: Some(log_path),
        }
    }

    fn sigkill(&mut self) {
        if let Some(ref child) = self.child {
            unsafe {
                libc::kill(child.id() as i32, libc::SIGKILL);
            }
            if let Some(mut c) = self.child.take() {
                let _ = c.wait();
            }
        }
    }

    fn kill(&mut self) {
        if let Some(ref mut child) = self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.child = None;
    }

    /// Print captured logs to stderr (for debugging test failures).
    #[allow(dead_code)]
    fn dump_logs(&self) {
        if let Some(ref path) = self.log_path
            && let Ok(content) = std::fs::read_to_string(path)
        {
            eprintln!("=== {} log ===\n{}", self.name, content);
        }
    }
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        self.kill();
    }
}

// ---------------------------------------------------------------------------
// HTTP client for host-agent
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct HostAgentClient {
    base_url: String,
    client: reqwest::Client,
}

impl HostAgentClient {
    fn new(port: u16) -> Self {
        Self {
            base_url: format!("http://127.0.0.1:{port}"),
            client: reqwest::Client::new(),
        }
    }

    async fn try_health(&self) -> Result<Value, reqwest::Error> {
        self.client
            .get(format!("{}/rpc/v1/health", self.base_url))
            .send()
            .await?
            .json()
            .await
    }

    async fn health(&self) -> Value {
        self.try_health().await.expect("health request failed")
    }

    async fn prepare(&self, sandbox_id: &str) -> Value {
        let resp = self
            .client
            .post(format!("{}/rpc/v1/prepare", self.base_url))
            .bearer_auth(HOST_TOKEN)
            .json(&json!({
                "spec": {
                    "id": sandbox_id,
                    "memory_mb": 64,
                    "vcpus": 1
                }
            }))
            .send()
            .await
            .expect("prepare request failed");
        let status = resp.status();
        let body_text = resp.text().await.unwrap_or_default();
        assert!(status.is_success(), "prepare failed: {status} {body_text}");
        serde_json::from_str(&body_text).unwrap_or_default()
    }

    async fn boot(&self, sandbox_id: &str) -> Value {
        let resp = self
            .client
            .post(format!("{}/rpc/v1/boot", self.base_url))
            .bearer_auth(HOST_TOKEN)
            .json(&json!({
                "sandbox_id": sandbox_id,
                "operation_id": format!("opr_boot_{sandbox_id}"),
                "assigned_host_id": HOST_ID,
                "assigned_cell_id": CELL_ID,
                "assignment_fencing_token": {"epoch": 1, "sequence": 1},
                "policy_epoch": 1,
                "timeout_secs": 60
            }))
            .send()
            .await
            .expect("boot request failed");
        let status = resp.status();
        let body_text = resp.text().await.unwrap_or_default();
        assert!(status.is_success(), "boot failed: {status} {body_text}");
        serde_json::from_str(&body_text).unwrap_or_default()
    }

    async fn exec(&self, sandbox_id: &str, command: &str) -> Result<Value, String> {
        let resp = self
            .client
            .post(format!("{}/rpc/v1/exec", self.base_url))
            .bearer_auth(HOST_TOKEN)
            .json(&json!({
                "sandbox_id": sandbox_id,
                "exec": {
                    "command": command,
                    "args": [],
                    "timeout_secs": 5
                }
            }))
            .send()
            .await
            .map_err(|e| format!("exec request failed: {e}"))?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if status.is_success() {
            Ok(serde_json::from_str(&body).unwrap_or_default())
        } else {
            Err(format!("exec failed: {status} body={body}"))
        }
    }

    async fn destroy(&self, sandbox_id: &str) -> Result<Value, String> {
        let resp = self
            .client
            .post(format!("{}/rpc/v1/destroy", self.base_url))
            .bearer_auth(HOST_TOKEN)
            .json(&json!({ "sandbox_id": sandbox_id }))
            .send()
            .await
            .map_err(|e| format!("destroy request failed: {e}"))?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if status.is_success() {
            Ok(serde_json::from_str(&body).unwrap_or_default())
        } else {
            Err(format!("destroy failed: {status} body={body}"))
        }
    }

    async fn wait_ready(&self) {
        let deadline = tokio::time::Instant::now() + TIMEOUT;
        loop {
            if let Ok(health) = self.try_health().await
                && health["status"] == "ready"
            {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "host-agent never became ready"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn wait_degraded(&self) {
        let deadline = tokio::time::Instant::now() + TIMEOUT;
        loop {
            if let Ok(health) = self.try_health().await
                && health["status"] == "degraded"
            {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "host-agent never became degraded after sandboxd kill"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn wait_reachable(&self) {
        let deadline = tokio::time::Instant::now() + TIMEOUT;
        loop {
            if self.try_health().await.is_ok() {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "host-agent never became reachable"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

// ---------------------------------------------------------------------------
// Test environment
// ---------------------------------------------------------------------------

struct TestEnv {
    dir: TempDir,
    socket_path: PathBuf,
    ledger_path: PathBuf,
    workspace_root: PathBuf,
    count_file: PathBuf,
    ssh_home: PathBuf,
    guest_socket: PathBuf,
    host_port: u16,
}

impl TestEnv {
    fn new() -> Self {
        let dir = TempDir::new().expect("tempdir");
        let socket_path = dir.path().join("sandboxd.sock");
        let ledger_path = dir.path().join("state.db");
        let workspace_root = dir.path().join("workspaces");
        std::fs::create_dir_all(&workspace_root).unwrap();
        let count_file = dir.path().join("backend_count");
        // The guest agent runs unprivileged on the CI host, so the default
        // SSH home (`/root`) is not writable. Point SSH key injection at a
        // tempdir-owned home instead; production never sets the override.
        let ssh_home = dir.path().join("ssh-home");
        std::fs::create_dir_all(&ssh_home).unwrap();
        Self {
            guest_socket: dir.path().join("guest.sock"),
            host_port: free_port(),
            dir,
            socket_path,
            ledger_path,
            workspace_root,
            count_file,
            ssh_home,
        }
    }

    fn log_dir(&self) -> &Path {
        self.dir.path()
    }

    fn spawn_sandboxd(&self, destroy_delay_ms: Option<u64>) -> ProcessGuard {
        let mut cmd = Command::new(sandboxd_bin());
        cmd.env(
            "PICO_SANDBOXD_SOCKET",
            self.socket_path.display().to_string(),
        )
        .env("PICO_SANDBOXD_TOKEN", SANDBOXD_TOKEN)
        .env(
            "PICO_SANDBOXD_STATE_PATH",
            self.ledger_path.display().to_string(),
        )
        .env(
            "PICO_WORKSPACE_ROOT",
            self.workspace_root.display().to_string(),
        )
        .env(
            "PICO_SANDBOXD_MOCK_GUEST_SOCKET",
            self.guest_socket.display().to_string(),
        )
        .env("PICO_SANDBOXD_ALLOW_MOCK", "1")
        .env(
            "PICO_SANDBOXD_MOCK_BACKEND_COUNT_FILE",
            self.count_file.display().to_string(),
        )
        .env("PICO_SANDBOXD_NETWORK", "disabled")
        // Mock guest serves the framed protocol on the Unix socket above;
        // that is the production guest transport for socket-based backends.
        .env("RUST_LOG", "info");
        if let Some(delay) = destroy_delay_ms {
            cmd.env("PICO_SANDBOXD_MOCK_DESTROY_DELAY_MS", delay.to_string());
        }
        ProcessGuard::spawn("sandboxd", &mut cmd, self.log_dir())
    }

    fn spawn_host_agent(&self) -> ProcessGuard {
        let mut cmd = Command::new(host_agent_bin());
        cmd.env(
            "PICO_HOST_AGENT_BIND_ADDR",
            format!("127.0.0.1:{}", self.host_port),
        )
        .env("PICO_HOST_AGENT_TOKEN", HOST_TOKEN)
        .env(
            "PICO_SANDBOXD_SOCKET",
            self.socket_path.display().to_string(),
        )
        .env("PICO_SANDBOXD_TOKEN", SANDBOXD_TOKEN)
        .env(
            "PICO_WORKSPACE_ROOT",
            self.workspace_root.display().to_string(),
        )
        .env("PICO_RUNTIME", "firecracker")
        .env("PICO_HOST_ID", HOST_ID)
        .env("PICO_CELL_ID", CELL_ID)
        .env("PICO_IDLE_TIMEOUT_SECS", "3600")
        .env("PICO_SSH_HOME_DIR", self.ssh_home.display().to_string())
        .env("RUST_LOG", "info");
        ProcessGuard::spawn("host-agent", &mut cmd, self.log_dir())
    }

    fn spawn_guest_agent(&self, sandbox_id: &str) -> ProcessGuard {
        let mut cmd = Command::new(guest_agent_bin());
        cmd.env("PICO_SANDBOX_ID", sandbox_id)
            .env(
                "PICO_GUEST_AGENT_SOCKET",
                self.guest_socket.display().to_string(),
            )
            .env("RUST_LOG", "info");
        ProcessGuard::spawn("guest-agent", &mut cmd, self.log_dir())
    }

    fn client(&self) -> HostAgentClient {
        HostAgentClient::new(self.host_port)
    }

    fn backend_create_count(&self) -> usize {
        std::fs::read_to_string(&self.count_file)
            .map(|content| content.lines().count())
            .unwrap_or(0)
    }

    async fn wait_for_socket(&self) {
        let deadline = tokio::time::Instant::now() + TIMEOUT;
        loop {
            if self.socket_path.exists()
                && tokio::net::UnixStream::connect(&self.socket_path)
                    .await
                    .is_ok()
            {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "sandboxd socket never became connectable at {:?}",
                self.socket_path
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn wait_for_guest_socket(&self) {
        let deadline = tokio::time::Instant::now() + TIMEOUT;
        loop {
            if tokio::net::UnixStream::connect(&self.guest_socket)
                .await
                .is_ok()
            {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "guest-agent never started listening on socket {:?}",
                self.guest_socket
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Polls the durable ledger until destroy intent is recorded.
    ///
    /// Mirrors the in-process test which polls `supervisor.status`
    /// until `Destroying`. Here we query the SQLite ledger directly because the
    /// binary harness has no in-process handle. A fixed sleep is flaky under CI
    /// load - the window can be too short (destroy never recorded, resume
    /// refuses) or destroy may not have started.
    async fn wait_for_destroy_intent(&self, sandbox_id: &str) {
        let deadline = tokio::time::Instant::now() + TIMEOUT;
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&self.ledger_path)
            .read_only(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_lazy_with(options);
        loop {
            let state: Option<String> =
                sqlx::query_scalar("SELECT observed_state FROM sandboxes WHERE sandbox_id = ?")
                    .bind(sandbox_id)
                    .fetch_optional(&pool)
                    .await
                    .unwrap_or(None);
            if state.as_deref() == Some("destroying") {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "destroy intent never reached ledger for {sandbox_id}, last observed_state={state:?}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    fn dump_logs(&self) {
        for name in ["sandboxd", "host-agent", "guest-agent"] {
            let path = self.log_dir().join(format!("{name}.log"));
            if let Ok(content) = std::fs::read_to_string(&path) {
                eprintln!("=== {name} log ({}) ===\n{content}", path.display());
            }
        }
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.dump_logs();
        }
    }
}

// ---------------------------------------------------------------------------
// Scenario 1: Agent restart keeps Running sandbox exec-able
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires pre-built binaries; run via dedicated CI job"]
async fn agent_restart_keeps_running_sandbox_execable() {
    require_binaries();
    let sandbox_id = "sbx_agent_restart";
    let env = TestEnv::new();

    let _guest = env.spawn_guest_agent(sandbox_id);
    env.wait_for_guest_socket().await;
    let _sandboxd = env.spawn_sandboxd(None);
    env.wait_for_socket().await;

    let mut host_agent = env.spawn_host_agent();
    let client = env.client();
    client.wait_ready().await;

    client.prepare(sandbox_id).await;
    let boot_report = client.boot(sandbox_id).await;
    assert_eq!(boot_report["status"], "ready", "boot should succeed");

    let exec_result = client.exec(sandbox_id, "echo").await;
    assert!(
        exec_result.is_ok(),
        "exec before restart: {:?}",
        exec_result.err()
    );

    // SIGKILL host-agent
    host_agent.sigkill();

    // Spawn a fresh host-agent against the same sandboxd
    let _host_agent2 = env.spawn_host_agent();
    client.wait_ready().await;

    // The new host-agent rehydrates from sandboxd; exec still works
    let exec_result = client.exec(sandbox_id, "echo").await;
    assert!(
        exec_result.is_ok(),
        "exec after host-agent restart: {:?}",
        exec_result.err()
    );
}

// ---------------------------------------------------------------------------
// Scenario 2: Daemon kill marks host not ready; no silent dual create
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires pre-built binaries; run via dedicated CI job"]
async fn daemon_kill_marks_host_not_ready_and_no_dual_create() {
    require_binaries();
    let sandbox_id = "sbx_daemon_kill";
    let env = TestEnv::new();

    let _guest = env.spawn_guest_agent(sandbox_id);
    env.wait_for_guest_socket().await;
    let mut sandboxd = env.spawn_sandboxd(None);
    env.wait_for_socket().await;

    let _host_agent = env.spawn_host_agent();
    let client = env.client();
    client.wait_ready().await;

    client.prepare(sandbox_id).await;
    client.boot(sandbox_id).await;

    let exec_result = client.exec(sandbox_id, "echo").await;
    assert!(
        exec_result.is_ok(),
        "exec before daemon kill: {:?}",
        exec_result.err()
    );

    let count_before = env.backend_create_count();
    assert_eq!(count_before, 1, "exactly one backend created");

    // SIGKILL sandboxd
    sandboxd.sigkill();

    // Host must report degraded while sandboxd is unreachable
    client.wait_degraded().await;

    // Restart sandboxd on the same ledger
    let _sandboxd2 = env.spawn_sandboxd(None);
    env.wait_for_socket().await;

    // Host recovers once sandboxd reconciles
    client.wait_ready().await;

    // No silent dual create: backend count unchanged
    let count_after = env.backend_create_count();
    assert_eq!(
        count_after, count_before,
        "daemon restart must not re-create the backend (dual create)"
    );

    // Host reports ready with the surviving sandbox still tracked
    let health = client.health().await;
    assert_eq!(health["status"], "ready");
    assert_eq!(health["sandbox_count"], 1);
}

// ---------------------------------------------------------------------------
// Scenario 3: Guest-session re-establishment after daemon restart
//
// After daemon restart, exec on the original sandbox must fail closed - the
// runtime handle and guest session are process-local and do not survive
// SIGKILL. This test proves two things:
// - The original sandbox stays quarantined (exec fails) until destroy+recreate;
//   same-sandbox re-handshake/reattach is explicitly out of scope (ADR-0011).
// - A *fresh* sandbox with a new guest-agent can still be created and booted
//   after the restart, proving the control plane recovered and can establish
//   new sessions. If the product contract ever requires transparent same-id
//   reattach, add a separate test that retries boot/attach on the original id.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires pre-built binaries; run via dedicated CI job"]
async fn exec_fails_closed_until_new_session_after_daemon_restart() {
    require_binaries();
    let sandbox_id = "sbx_session_restart";
    let env = TestEnv::new();

    let _guest = env.spawn_guest_agent(sandbox_id);
    env.wait_for_guest_socket().await;
    let mut sandboxd = env.spawn_sandboxd(None);
    env.wait_for_socket().await;

    let _host_agent = env.spawn_host_agent();
    let client = env.client();
    client.wait_ready().await;

    // Real guest-agent handshake completes during boot
    client.prepare(sandbox_id).await;
    let boot_report = client.boot(sandbox_id).await;
    assert_eq!(boot_report["status"], "ready");

    // Exec works with active session
    let exec_result = client.exec(sandbox_id, "echo").await;
    assert!(
        exec_result.is_ok(),
        "exec with live session: {:?}",
        exec_result.err()
    );

    // SIGKILL sandboxd: guest session dies with the daemon
    sandboxd.sigkill();

    // Restart sandboxd on the same ledger
    let _sandboxd2 = env.spawn_sandboxd(None);
    env.wait_for_socket().await;
    client.wait_ready().await;

    // Exec must fail closed: runtime handle and session are gone
    let exec_result = client.exec(sandbox_id, "echo").await;
    assert!(
        exec_result.is_err(),
        "exec must fail closed after daemon restart (session lost)"
    );

    // A fresh sandbox with a new guest-agent proves re-establishment works
    let new_id = "sbx_session_fresh";
    drop(_guest);
    // Brief pause to let the OS release the port
    tokio::time::sleep(Duration::from_millis(500)).await;
    let _guest2 = env.spawn_guest_agent(new_id);
    env.wait_for_guest_socket().await;

    client.prepare(new_id).await;
    let boot_report = client.boot(new_id).await;
    assert_eq!(
        boot_report["status"], "ready",
        "new sandbox boots after daemon restart"
    );

    let exec_result = client.exec(new_id, "echo").await;
    assert!(
        exec_result.is_ok(),
        "exec on fresh sandbox: {:?}",
        exec_result.err()
    );
}

// ---------------------------------------------------------------------------
// Scenario 4: Mid-destroy cleanup resumes from ledger
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires pre-built binaries; run via dedicated CI job"]
async fn mid_destroy_cleanup_resumes_from_ledger_after_restart() {
    require_binaries();
    let sandbox_id = "sbx_mid_destroy";
    let env = TestEnv::new();

    let _guest = env.spawn_guest_agent(sandbox_id);
    env.wait_for_guest_socket().await;
    // Long destroy delay so we can SIGKILL mid-operation
    let mut sandboxd = env.spawn_sandboxd(Some(600_000));
    env.wait_for_socket().await;

    let mut host_agent = env.spawn_host_agent();
    let client = env.client();
    client.wait_ready().await;

    client.prepare(sandbox_id).await;
    client.boot(sandbox_id).await;

    // Verify workspace exists
    let ws_path = env.workspace_root.join(sandbox_id);
    assert!(ws_path.exists(), "workspace should exist after boot");

    // Issue destroy in background (will block on mock delay)
    let destroy_client = client.clone();
    let destroy_id = sandbox_id.to_string();
    let destroy_handle = tokio::spawn(async move { destroy_client.destroy(&destroy_id).await });

    // Wait for destroy intent to reach the ledger (begin() records before
    // backend.destroy() blocks on the mock delay). Polling is more robust than
    // a fixed sleep - under CI load the sleep window can be too short or the
    // RPC may not have started.
    env.wait_for_destroy_intent(sandbox_id).await;

    // SIGKILL sandboxd mid-destroy
    sandboxd.sigkill();
    // The pending gRPC call may hang until its client-side timeout; don't
    // block the test waiting for it.
    let _ = tokio::time::timeout(Duration::from_secs(5), destroy_handle).await;

    // Kill host-agent too (its local state is stale after the failed RPC)
    host_agent.sigkill();

    // Restart sandboxd WITHOUT the delay; reconcile marks the interrupted op
    let _sandboxd2 = env.spawn_sandboxd(None);
    env.wait_for_socket().await;

    // Restart host-agent; it rehydrates from sandboxd's ledger
    let _host_agent2 = env.spawn_host_agent();
    // Health reports degraded due to review findings from the interrupted op,
    // so we only wait for reachability rather than full readiness.
    client.wait_reachable().await;

    // Retry destroy: the ledger preserves the intent, and without the delay
    // the mock backend completes immediately
    let result = client.destroy(sandbox_id).await;
    assert!(
        result.is_ok(),
        "destroy retry after restart should succeed: {:?}",
        result.err()
    );

    // Workspace directory must be cleaned up
    assert!(
        !ws_path.exists(),
        "workspace must be removed after successful destroy"
    );
}

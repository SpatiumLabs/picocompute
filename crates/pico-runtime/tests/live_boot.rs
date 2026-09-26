//! Live isolation-backend boot evidence (ignored-walk harness with CI wiring).
//!
//! One ignored test per preview backend walks a single live
//! prepare/boot/attach/wait-ready/exec/destroy lifecycle (plus suspend/resume
//! where the backend actually pauses the guest) and writes a JSON evidence
//! bundle. The bundle captures the host profile (including host image and
//! kernel), source revision, VMM and helper versions,
//! guest artifact digests, the transport actually used (vsock UDS, Unix, never
//! TCP in production configs), per-phase outcomes, and log tails.
//!
//! Run via the collector script, which adds host preflight and aggregates the
//! per-backend bundles:
//!
//! ```bash
//! scripts/live-boot-evidence.sh
//! ```
//!
//! Or run a single backend directly (Linux KVM host with guest assets):
//!
//! ```bash
//! LIVE_BOOT_OUT_DIR=/tmp/live-boot cargo nextest run -p pico-runtime \
//!   --test live_boot --run-ignored ignored-only
//! ```
//!
//! Scoping notes, read before interpreting a bundle:
//!
//! - Adapter `wait_ready` for `Vsock`/`Unix` transports is accept-only; the
//!   production guest handshake over those transports is owned by
//!   `sandboxd::establish_guest_session` (pinned by the sandboxd
//!   `qemu_transport` integration test with a mock Unix guest). The bundle
//!   records this explicitly instead of claiming adapter-level handshake
//!   proof.
//! - Firecracker suspend/resume is state-only (issue 135) so the harness skips
//!   it rather than recording a fake pause.
//! - After the accept-only vsock `wait_ready`, the Firecracker harness polls
//!   the TAP-routed guest-agent port (`wait_guest_agent`, fail-closed on a
//!   deadline) as a guest-liveness signal before recording observability.
//! - The guest agent serves its port inside the guest. Adapter-level exec is
//!   not supported for Firecracker/QEMU (guest sessions are owned by
//!   sandboxd), so those walks skip adapter exec and record the reason;
//!   gVisor `exec` works via `runsc exec` and is probed directly.
//!   Production exec is owned by sandboxd over vsock/Unix.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use pico_core::{ExecRequest, GuestTransport, RuntimeBackend, SandboxConfig, SandboxState};
use serde_json::{Map, Value};

const SCHEMA_VERSION: &str = "live-boot-evidence/1";
const TAIL_MAX_LINES: usize = 50;
const TAIL_MAX_BYTES: usize = 8192;
const VERSION_MAX_BYTES: usize = 2048;

fn out_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("LIVE_BOOT_OUT_DIR") {
        return PathBuf::from(dir);
    }
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/live-boot-evidence")
}

fn live_timeout() -> Duration {
    std::env::var("LIVE_BOOT_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(600))
}

fn sandbox_id_for(tag: &str) -> String {
    format!("sbx-live-{tag}-{}", std::process::id())
}

fn elapsed_ms(start: &Instant) -> u64 {
    start.elapsed().as_millis() as u64
}

/// Runs `bin --version` and returns trimmed output, or `None` when the binary
/// cannot be executed.
fn run_cmd(bin: &Path, args: &[&str]) -> Option<String> {
    let output = std::process::Command::new(bin).args(args).output().ok()?;
    let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.trim().is_empty() {
        if !combined.trim().is_empty() {
            combined.push('\n');
        }
        combined.push_str(stderr.trim());
    }
    let trimmed = combined.trim().to_string();
    if trimmed.is_empty() {
        return None;
    }
    Some(truncate_bytes(&trimmed, VERSION_MAX_BYTES))
}

fn truncate_bytes(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut end = max_bytes;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...[truncated]", &s[..end])
}

/// Resolves a configured binary path: absolute/relative paths must exist,
/// bare names are searched on `PATH`.
fn resolve_binary(path: &Path) -> Option<PathBuf> {
    if path.components().count() > 1 {
        return path.exists().then(|| path.to_path_buf());
    }
    let name = path.as_os_str();
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).find_map(|dir| {
            let candidate = dir.join(name);
            if candidate.is_file() {
                Some(candidate)
            } else {
                None
            }
        })
    })
}

fn binary_version_entry(path: &Path) -> Value {
    let resolved = resolve_binary(path);
    let version = resolved
        .as_deref()
        .and_then(|bin| run_cmd(bin, &["--version"]));
    serde_json::json!({
        "configured_path": path.display().to_string(),
        "resolved_path": resolved.map(|p| p.display().to_string()),
        "version": version,
    })
}

fn sha256_file(path: &Path) -> Option<String> {
    use sha2::Digest as _;
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = sha2::Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        use std::io::Read as _;
        let n = file.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest.iter() {
        hex.push_str(&format!("{byte:02x}"));
    }
    Some(hex)
}

fn artifact_entry(path: &Path) -> Value {
    let exists = path.is_file();
    serde_json::json!({
        "path": path.display().to_string(),
        "exists": exists,
        "sha256": if exists { sha256_file(path) } else { None },
    })
}

fn opt_artifact_entry(path: Option<&Path>) -> Value {
    match path {
        Some(p) => artifact_entry(p),
        None => serde_json::json!({"path": null, "exists": false, "sha256": null}),
    }
}

fn tail_file(path: &Path, max_lines: usize, max_bytes: usize) -> Option<String> {
    let contents = std::fs::read_to_string(path).ok()?;
    let lines: Vec<&str> = contents.lines().collect();
    let start = lines.len().saturating_sub(max_lines);
    let tail = lines[start..].join("\n");
    Some(truncate_bytes(&tail, max_bytes))
}

fn host_profile() -> Value {
    let kernel = std::fs::read_to_string("/proc/version")
        .ok()
        .map(|s| s.trim().to_string())
        .or_else(|| run_cmd(Path::new("uname"), &["-a"]));
    let kernel_release = run_cmd(Path::new("uname"), &["-r"]);
    let cpu = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|info| {
            info.lines()
                .find(|l| l.starts_with("model name"))
                .and_then(|l| l.split_once(':'))
                .map(|(_, m)| m.trim().to_string())
        });
    let os_release = os_release_map();
    let host_image = host_image_id(&os_release);
    serde_json::json!({
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "kernel": kernel,
        "kernel_release": kernel_release,
        "host_image": host_image,
        "os_release": os_release,
        "cpu_model": cpu,
        "kvm_present": Path::new("/dev/kvm").exists(),
        "vhost_vsock_present": Path::new("/dev/vhost-vsock").exists(),
    })
}

/// Parses `/etc/os-release` into a string map. Empty when the file is absent
/// (for example macOS dev hosts); the bundle still records what is known.
fn os_release_map() -> Map<String, Value> {
    let mut map = Map::new();
    let Ok(contents) = std::fs::read_to_string("/etc/os-release") else {
        return map;
    };
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            // os-release values may be single- or double-quoted; strip one
            // matching pair so identifiers compare cleanly.
            let v = v.trim();
            let unquoted = v
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .or_else(|| v.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
                .unwrap_or(v);
            map.insert(k.trim().to_string(), Value::String(unquoted.to_string()));
        }
    }
    map
}

/// Human-readable host image identifier for the evidence bundle. Prefers an
/// explicit `LIVE_BOOT_HOST_IMAGE` override (release-candidate naming), then
/// `/etc/os-release` `PRETTY_NAME`, then `NAME` plus `VERSION_ID`.
fn host_image_id(os_release: &Map<String, Value>) -> Option<String> {
    if let Ok(override_image) = std::env::var("LIVE_BOOT_HOST_IMAGE") {
        let trimmed = override_image.trim().to_string();
        if !trimmed.is_empty() {
            return Some(trimmed);
        }
    }
    let str_field = |key: &str| {
        os_release
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    if let Some(pretty) = str_field("PRETTY_NAME") {
        return Some(pretty);
    }
    match (str_field("NAME"), str_field("VERSION_ID")) {
        (Some(name), Some(version)) => Some(format!("{name} {version}")),
        (Some(name), None) => Some(name),
        (None, _) => None,
    }
}

/// Tested source revision attached to every bundle so evidence links to a
/// revision. Prefers `GITHUB_SHA` (CI), then `git rev-parse HEAD`, else
/// `"unknown"`. Dirty state is best-effort and never fails the walk.
fn source_revision() -> Value {
    if let Ok(sha) = std::env::var("GITHUB_SHA") {
        let sha = sha.trim().to_string();
        if !sha.is_empty() {
            return serde_json::json!({
                "revision": sha,
                "dirty": source_dirty(),
                "source": "env:GITHUB_SHA",
            });
        }
    }
    let revision = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .and_then(|out| {
            if out.status.success() {
                let sha = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if sha.is_empty() { None } else { Some(sha) }
            } else {
                None
            }
        })
        .unwrap_or_else(|| "unknown".to_string());
    let source = if revision == "unknown" {
        "unknown"
    } else {
        "git:rev-parse HEAD"
    };
    serde_json::json!({
        "revision": revision,
        "dirty": source_dirty(),
        "source": source,
    })
}

fn source_dirty() -> Option<bool> {
    std::process::Command::new("git")
        .args(["status", "--porcelain=v1"])
        .output()
        .ok()
        .and_then(|out| {
            if out.status.success() {
                Some(!String::from_utf8_lossy(&out.stdout).trim().is_empty())
            } else {
                None
            }
        })
}

/// Accumulates the evidence bundle and guarantees a JSON file is written even
/// when the walk aborts through an unexpected panic.
struct Evidence {
    backend: &'static str,
    sandbox_id: String,
    started_at: String,
    out_path: PathBuf,
    host: Value,
    source_revision: Value,
    versions: Map<String, Value>,
    artifacts: Map<String, Value>,
    phases: Vec<Value>,
    log_tails: Map<String, Value>,
    extra: Map<String, Value>,
    finished: bool,
}

impl Evidence {
    fn new(backend: &'static str, tag: &str) -> Self {
        let sandbox_id = sandbox_id_for(tag);
        let out_path = out_dir().join(format!("{backend}.json"));
        Self {
            backend,
            sandbox_id,
            started_at: pico_core::now_iso(),
            out_path,
            host: host_profile(),
            source_revision: source_revision(),
            versions: Map::new(),
            artifacts: Map::new(),
            phases: Vec::new(),
            log_tails: Map::new(),
            extra: Map::new(),
            finished: false,
        }
    }

    fn phase(&mut self, name: &str, ok: bool, latency_ms: u64, detail: Option<String>) {
        self.phases.push(serde_json::json!({
            "name": name,
            "ok": ok,
            "latency_ms": latency_ms,
            "detail": detail,
        }));
    }

    fn phase_skipped(&mut self, name: &str, reason: &str) {
        self.phases.push(serde_json::json!({
            "name": name,
            "ok": true,
            "skipped": true,
            "latency_ms": 0,
            "detail": reason,
        }));
    }

    fn collect_tails(&mut self, artifacts: &[String]) {
        for artifact in artifacts {
            let path = Path::new(artifact);
            if !path.is_file() {
                continue;
            }
            let key = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| artifact.clone());
            if self.log_tails.contains_key(&key) {
                self.log_tails.insert(
                    artifact.clone(),
                    Value::String(
                        tail_file(path, TAIL_MAX_LINES, TAIL_MAX_BYTES)
                            .unwrap_or_else(|| "<unreadable>".to_string()),
                    ),
                );
            } else {
                self.log_tails.insert(
                    key,
                    Value::String(
                        tail_file(path, TAIL_MAX_LINES, TAIL_MAX_BYTES)
                            .unwrap_or_else(|| "<unreadable>".to_string()),
                    ),
                );
            }
        }
    }

    fn finish(&mut self, status: &str, message: Option<String>) {
        self.finished = true;
        let doc = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "backend": self.backend,
            "sandbox_id": self.sandbox_id,
            "started_at": self.started_at,
            "ended_at": pico_core::now_iso(),
            "status": status,
            "message": message,
            "adapter_version": env!("CARGO_PKG_VERSION"),
            "source_revision": self.source_revision,
            "host": self.host,
            "versions": self.versions,
            "artifacts": self.artifacts,
            "transport": self.extra.remove("transport").unwrap_or(Value::Null),
            "phases": self.phases,
            "exec": self.extra.remove("exec").unwrap_or(Value::Null),
            "suspend_resume": self.extra.remove("suspend_resume").unwrap_or(Value::Null),
            "stats": self.extra.remove("stats").unwrap_or(Value::Null),
            "health": self.extra.remove("health").unwrap_or(Value::Null),
            "diagnostics": self.extra.remove("diagnostics").unwrap_or(Value::Null),
            "log_tails": self.log_tails,
            "notes": self.extra,
        });
        if let Some(parent) = self.out_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let text = serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".to_string());
        let _ = std::fs::write(&self.out_path, text);
    }
}

impl Drop for Evidence {
    fn drop(&mut self) {
        if !self.finished {
            self.finish("interrupted", Some("walk ended without finish".to_string()));
        }
    }
}

fn block(ev: &mut Evidence, reasons: &[String]) -> ! {
    let reason = reasons.join("; ");
    ev.phase("preflight", false, 0, Some(reason.clone()));
    ev.finish("blocked", Some(reason.clone()));
    panic!("live boot blocked: {reason}");
}

fn fail(phase: &str, ev: &mut Evidence, err: String) -> ! {
    ev.finish("failed", Some(format!("{phase}: {err}")));
    panic!("live boot failed at {phase}: {err}");
}

/// Best-effort diagnostics plus destroy after a mid-walk failure, then fail.
async fn abort_walk(
    ev: &mut Evidence,
    backend: &dyn RuntimeBackend,
    phase: &str,
    err: String,
) -> ! {
    match backend.diagnostics().await {
        Ok(bundle) => {
            ev.extra.insert(
                "diagnostics_summary_on_failure".to_string(),
                Value::String(bundle.summary),
            );
            ev.collect_tails(&bundle.artifacts);
        }
        Err(e) => {
            ev.phase("diagnostics_on_failure", false, 0, Some(e.to_string()));
        }
    }
    match backend.destroy().await {
        Ok(report) => {
            ev.phase(
                "destroy_on_failure",
                true,
                0,
                Some(format!("remaining={:?}", report.remaining)),
            );
        }
        Err(e) => {
            ev.phase("destroy_on_failure", false, 0, Some(e.to_string()));
        }
    }
    fail(phase, ev, err);
}

fn exec_request(command: &str, args: &[&str]) -> ExecRequest {
    ExecRequest {
        command: command.to_string(),
        args: args.iter().map(|a| a.to_string()).collect(),
        env: None,
        working_dir: None,
        timeout_secs: Some(30),
    }
}

fn live_sandbox_config(sandbox_id: &str) -> SandboxConfig {
    SandboxConfig {
        id: sandbox_id.to_string(),
        memory_limit_bytes: 512 * 1024 * 1024,
        network_isolated: true,
        ..Default::default()
    }
}

/// Destroys the adapter after an outer timeout so a hung boot does not leave
/// a VMM/runsc process behind, then records `failed`.
async fn fail_after_timeout(
    ev: &mut Evidence,
    backend: &dyn RuntimeBackend,
    timeout: Duration,
) -> ! {
    match backend.destroy().await {
        Ok(report) => {
            ev.phase(
                "destroy_on_timeout",
                true,
                0,
                Some(format!("remaining={:?}", report.remaining)),
            );
        }
        Err(e) => {
            ev.phase("destroy_on_timeout", false, 0, Some(e.to_string()));
        }
    }
    fail(
        "walk",
        ev,
        format!("outer timeout of {}s exceeded", timeout.as_secs()),
    );
}

async fn check_state(
    ev: &mut Evidence,
    backend: &dyn RuntimeBackend,
    phase: &str,
    expected: SandboxState,
) {
    match backend.state().await {
        Ok(actual) if actual == expected => {
            ev.phase(phase, true, 0, Some(format!("state={actual}")));
        }
        Ok(actual) => {
            abort_walk(
                ev,
                backend,
                phase,
                format!("expected state {expected}, observed {actual}"),
            )
            .await;
        }
        Err(e) => abort_walk(ev, backend, phase, format!("state() failed: {e}")).await,
    }
}

// ---------------------------------------------------------------------------
// Firecracker
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a Linux KVM host with firecracker/jailer binaries, guest kernel/rootfs assets, and TAP networking"]
async fn firecracker_live_boot_evidence() {
    let t0 = Instant::now();
    let mut ev = Evidence::new("firecracker", "fc");
    let cfg = pico_runtime::firecracker::config::FirecrackerConfig::detect_defaults();

    ev.versions.insert(
        "firecracker".to_string(),
        binary_version_entry(&cfg.firecracker_binary_path),
    );
    if let Some(jailer) = &cfg.jailer_binary_path {
        ev.versions
            .insert("jailer".to_string(), binary_version_entry(jailer));
    } else {
        ev.versions.insert(
            "jailer".to_string(),
            serde_json::json!({"configured_path": null, "note": "jailer not configured; VMM runs without jailer confinement"}),
        );
    }
    ev.artifacts
        .insert("kernel".to_string(), artifact_entry(&cfg.kernel.image_path));
    ev.artifacts
        .insert("rootfs".to_string(), artifact_entry(&cfg.rootfs_path));
    ev.artifacts.insert(
        "initrd".to_string(),
        opt_artifact_entry(cfg.initrd_path.as_deref()),
    );

    let mut missing = Vec::new();
    if std::env::consts::OS != "linux" {
        missing.push(format!(
            "host OS is {} (Firecracker needs a Linux KVM host)",
            std::env::consts::OS
        ));
    }
    if !Path::new("/dev/kvm").exists() {
        missing.push("/dev/kvm not present".to_string());
    }
    if resolve_binary(&cfg.firecracker_binary_path).is_none() {
        missing.push(format!(
            "firecracker binary not found at {} (PICO_FIRECRACKER_BIN or PATH)",
            cfg.firecracker_binary_path.display()
        ));
    }
    if !cfg.kernel.image_path.is_file() {
        missing.push(format!(
            "guest kernel not found at {}",
            cfg.kernel.image_path.display()
        ));
    }
    if !cfg.rootfs_path.is_file() {
        missing.push(format!(
            "guest rootfs not found at {}",
            cfg.rootfs_path.display()
        ));
    }
    if let Some(initrd) = &cfg.initrd_path
        && !initrd.is_file()
    {
        missing.push(format!("initrd not found at {}", initrd.display()));
    }
    if !missing.is_empty() {
        block(&mut ev, &missing);
    }
    ev.phase(
        "preflight",
        true,
        elapsed_ms(&t0),
        Some("KVM, binaries, and guest assets present; vsock required".to_string()),
    );

    let adapter = pico_runtime::firecracker::FirecrackerAdapter::with_config(cfg);
    let timeout = live_timeout();
    if tokio::time::timeout(timeout, walk_firecracker(&mut ev, &adapter))
        .await
        .is_err()
    {
        fail_after_timeout(&mut ev, &adapter, timeout).await;
    }
}

async fn walk_firecracker(ev: &mut Evidence, backend: &dyn RuntimeBackend) {
    ev.extra.insert(
        "metadata".to_string(),
        serde_json::to_value(backend.metadata()).unwrap_or(Value::Null),
    );

    let t0 = Instant::now();
    match backend.prepare(&live_sandbox_config(&ev.sandbox_id)).await {
        Ok(prepared) => ev.phase(
            "prepare",
            true,
            elapsed_ms(&t0),
            Some(format!("receipts={:?}", prepared.resources)),
        ),
        Err(e) => abort_walk(ev, backend, "prepare", e.to_string()).await,
    }

    let t0 = Instant::now();
    if let Err(e) = backend.boot().await {
        abort_walk(ev, backend, "boot", e.to_string()).await;
    }
    ev.phase("boot", true, elapsed_ms(&t0), None);
    check_state(ev, backend, "state_after_boot", SandboxState::Running).await;

    let t0 = Instant::now();
    let transport = match backend.attach_transport().await {
        Ok(t) => {
            ev.phase("attach_transport", true, elapsed_ms(&t0), None);
            t
        }
        Err(e) => abort_walk(ev, backend, "attach_transport", e.to_string()).await,
    };
    match &transport {
        GuestTransport::Vsock {
            uds_path: Some(_), ..
        } => {}
        other => {
            abort_walk(
                ev,
                backend,
                "attach_transport",
                format!("production Firecracker attach must be vsock+UDS, got {other:?}"),
            )
            .await;
        }
    }
    ev.extra.insert(
        "transport".to_string(),
        serde_json::json!({
            "expected": "vsock+uds",
            "observed": serde_json::to_value(&transport).unwrap_or(Value::Null),
            "production_ok": true,
        }),
    );

    let t0 = Instant::now();
    if let Err(e) = backend.wait_ready(&transport).await {
        abort_walk(ev, backend, "wait_ready", e.to_string()).await;
    }
    ev.phase(
        "wait_ready",
        true,
        elapsed_ms(&t0),
        Some("adapter accept-only for vsock; production handshake is owned by sandboxd establish_guest_session".to_string()),
    );

    wait_for_guest_tcp(ev, backend).await;

    // Adapter exec is not supported: guest sessions are owned by sandboxd
    // over the attached vsock transport. The walk records lifecycle,
    // transport, and observability evidence; exec is proven through the
    // supervisor session, not the adapter.
    ev.phase_skipped(
        "exec_true",
        "skipped: direct adapter exec is not supported; production exec is sandboxd over vsock",
    );
    ev.phase_skipped(
        "exec_printf",
        "skipped: direct adapter exec is not supported; production exec is sandboxd over vsock",
    );
    ev.extra.insert(
        "exec".to_string(),
        serde_json::json!({
            "attempted": false,
            "reason": "adapter-exec-owned-by-sandboxd",
        }),
    );
    run_observability(ev, backend).await;

    // Firecracker suspend/resume is state-only (issue 135): it does not pause
    // the guest, so there is no pause to prove. Skip rather than fake it.
    ev.phase_skipped(
        "suspend_resume",
        "skipped: Firecracker suspend/resume is state-only (issue 135); no guest pause to prove",
    );
    ev.extra.insert(
        "suspend_resume".to_string(),
        serde_json::json!({"attempted": false, "reason": "firecracker-suspend-state-only"}),
    );

    destroy_and_cleanup(ev, backend).await;
    ev.finish("pass", None);
}

// ---------------------------------------------------------------------------
// QEMU
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a Linux KVM host with a QEMU binary, guest kernel/rootfs assets, and vhost-vsock for vsock mode"]
async fn qemu_live_boot_evidence() {
    let t0 = Instant::now();
    let mut ev = Evidence::new("qemu", "qemu");
    let cfg = pico_runtime::qemu::config::QemuConfig::detect_defaults();

    ev.versions.insert(
        "qemu".to_string(),
        binary_version_entry(&cfg.qemu_binary_path),
    );
    ev.artifacts
        .insert("kernel".to_string(), artifact_entry(&cfg.kernel.image_path));
    ev.artifacts
        .insert("rootfs".to_string(), artifact_entry(&cfg.rootfs_path));
    ev.extra.insert(
        "qemu_config".to_string(),
        serde_json::json!({
            "mode": format!("{:?}", cfg.mode),
            "accelerator": cfg.accelerator,
            "enable_vsock": cfg.enable_vsock,
            "serial_fallback": cfg.serial_fallback,
            "qmp_enabled": cfg.qmp_enabled,
            "vsock_port": cfg.vsock_port,
        }),
    );

    let mut missing = Vec::new();
    if resolve_binary(&cfg.qemu_binary_path).is_none() {
        missing.push(format!(
            "qemu binary not found at {} (PICO_QEMU_BIN or PATH)",
            cfg.qemu_binary_path.display()
        ));
    }
    if !cfg.kernel.image_path.is_file() {
        missing.push(format!(
            "guest kernel not found at {}",
            cfg.kernel.image_path.display()
        ));
    }
    if !cfg.rootfs_path.is_file() {
        missing.push(format!(
            "guest rootfs not found at {}",
            cfg.rootfs_path.display()
        ));
    }
    if cfg.accelerator.contains("kvm") && !Path::new("/dev/kvm").exists() {
        missing.push(format!(
            "accelerator {} needs /dev/kvm, which is not present",
            cfg.accelerator
        ));
    }
    if cfg.enable_vsock && !Path::new("/dev/vhost-vsock").exists() {
        missing.push(
            "enable_vsock=true but /dev/vhost-vsock is not present (vhost-vsock-pci needs it)"
                .to_string(),
        );
    }
    if !cfg.enable_vsock && !cfg.serial_fallback {
        missing.push(
            "live-boot evidence requires vsock or the serial fallback; neither is enabled"
                .to_string(),
        );
    }
    if !missing.is_empty() {
        block(&mut ev, &missing);
    }
    ev.phase(
        "preflight",
        true,
        elapsed_ms(&t0),
        Some("binaries, guest assets, and accelerator/vsock prerequisites present".to_string()),
    );

    let qmp_enabled = cfg.qmp_enabled;
    let adapter = pico_runtime::qemu::QemuAdapter::with_config(cfg);
    let timeout = live_timeout();
    if tokio::time::timeout(timeout, walk_qemu(&mut ev, &adapter, qmp_enabled))
        .await
        .is_err()
    {
        fail_after_timeout(&mut ev, &adapter, timeout).await;
    }
}

async fn walk_qemu(ev: &mut Evidence, backend: &dyn RuntimeBackend, qmp_enabled: bool) {
    ev.extra.insert(
        "metadata".to_string(),
        serde_json::to_value(backend.metadata()).unwrap_or(Value::Null),
    );

    let t0 = Instant::now();
    match backend.prepare(&live_sandbox_config(&ev.sandbox_id)).await {
        Ok(prepared) => ev.phase(
            "prepare",
            true,
            elapsed_ms(&t0),
            Some(format!("receipts={:?}", prepared.resources)),
        ),
        Err(e) => abort_walk(ev, backend, "prepare", e.to_string()).await,
    }

    let t0 = Instant::now();
    if let Err(e) = backend.boot().await {
        abort_walk(ev, backend, "boot", e.to_string()).await;
    }
    ev.phase("boot", true, elapsed_ms(&t0), None);
    check_state(ev, backend, "state_after_boot", SandboxState::Running).await;

    let t0 = Instant::now();
    let transport = match backend.attach_transport().await {
        Ok(t) => {
            ev.phase("attach_transport", true, elapsed_ms(&t0), None);
            t
        }
        Err(e) => abort_walk(ev, backend, "attach_transport", e.to_string()).await,
    };
    let production_ok = matches!(
        &transport,
        GuestTransport::Vsock { .. } | GuestTransport::Unix { .. }
    );
    if !production_ok {
        abort_walk(
            ev,
            backend,
            "attach_transport",
            format!("production QEMU attach must be vsock or Unix, got {transport:?}"),
        )
        .await;
    }
    ev.extra.insert(
        "transport".to_string(),
        serde_json::json!({
            "expected": "vsock (or gated serial Unix fallback)",
            "observed": serde_json::to_value(&transport).unwrap_or(Value::Null),
            "production_ok": true,
        }),
    );

    let t0 = Instant::now();
    if let Err(e) = backend.wait_ready(&transport).await {
        abort_walk(ev, backend, "wait_ready", e.to_string()).await;
    }
    ev.phase(
        "wait_ready",
        true,
        elapsed_ms(&t0),
        Some("adapter accept-only for vsock/Unix; production handshake is owned by sandboxd establish_guest_session".to_string()),
    );

    // Direct adapter exec is not supported: guest sessions are owned by
    // sandboxd over the attached transport. Requiring exec here would make
    // the walk unpassable. Production exec is sandboxd over vsock/Unix.
    ev.phase_skipped(
        "exec_true",
        "skipped: direct adapter exec is not supported; production exec is sandboxd over vsock/Unix",
    );
    ev.phase_skipped(
        "exec_printf",
        "skipped: direct adapter exec is not supported; production exec is sandboxd over vsock/Unix",
    );
    ev.extra.insert(
        "exec".to_string(),
        serde_json::json!({
            "attempted": false,
            "reason": "adapter-exec-owned-by-sandboxd",
        }),
    );
    run_observability(ev, backend).await;

    // QEMU suspend/resume drives QMP stop/cont when qmp_enabled, which
    // actually pauses the guest. Without QMP it is a state transition only,
    // so the harness skips it rather than recording a fake pause.
    if qmp_enabled {
        let t0 = Instant::now();
        if let Err(e) = backend.suspend().await {
            abort_walk(ev, backend, "suspend", e.to_string()).await;
        }
        ev.phase(
            "suspend",
            true,
            elapsed_ms(&t0),
            Some("QMP stop".to_string()),
        );
        check_state(ev, backend, "state_after_suspend", SandboxState::Suspended).await;

        let t0 = Instant::now();
        if let Err(e) = backend.resume().await {
            abort_walk(ev, backend, "resume", e.to_string()).await;
        }
        ev.phase(
            "resume",
            true,
            elapsed_ms(&t0),
            Some("QMP cont".to_string()),
        );
        check_state(ev, backend, "state_after_resume", SandboxState::Running).await;
        ev.phase_skipped(
            "exec_after_resume",
            "skipped: direct adapter exec is not supported; QMP stop/cont already proved the pause",
        );
        ev.extra.insert(
            "suspend_resume".to_string(),
            serde_json::json!({"attempted": true, "mechanism": "qmp-stop-cont"}),
        );
    } else {
        ev.phase_skipped(
            "suspend_resume",
            "skipped: qmp_enabled=false, so suspend/resume would be state-only with no guest pause",
        );
        ev.extra.insert(
            "suspend_resume".to_string(),
            serde_json::json!({"attempted": false, "reason": "qmp-disabled-state-only"}),
        );
    }

    destroy_and_cleanup(ev, backend).await;
    ev.finish("pass", None);
}

// ---------------------------------------------------------------------------
// gVisor
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a Linux host with a runsc binary and a gVisor rootfs"]
async fn gvisor_live_boot_evidence() {
    let t0 = Instant::now();
    let mut ev = Evidence::new("gvisor", "gv");
    let cfg = pico_runtime::gvisor::config::GVisorConfig::detect_defaults();

    ev.versions.insert(
        "runsc".to_string(),
        binary_version_entry(&cfg.runsc_binary_path),
    );
    ev.artifacts
        .insert("rootfs".to_string(), artifact_entry(&cfg.guest_rootfs_path));

    let mut missing = Vec::new();
    if std::env::consts::OS != "linux" {
        missing.push(format!(
            "host OS is {} (runsc needs Linux)",
            std::env::consts::OS
        ));
    }
    if resolve_binary(&cfg.runsc_binary_path).is_none() {
        missing.push(format!(
            "runsc binary not found at {} (PATH or GVisorConfig)",
            cfg.runsc_binary_path.display()
        ));
    }
    if !cfg.guest_rootfs_path.exists() {
        missing.push(format!(
            "gVisor rootfs not found at {}",
            cfg.guest_rootfs_path.display()
        ));
    }
    if !missing.is_empty() {
        block(&mut ev, &missing);
    }
    ev.phase(
        "preflight",
        true,
        elapsed_ms(&t0),
        Some("runsc and rootfs present".to_string()),
    );

    let adapter = pico_runtime::gvisor::GVisorAdapter::with_config(cfg);
    let timeout = live_timeout();
    if tokio::time::timeout(timeout, walk_gvisor(&mut ev, &adapter))
        .await
        .is_err()
    {
        fail_after_timeout(&mut ev, &adapter, timeout).await;
    }
}

async fn walk_gvisor(ev: &mut Evidence, backend: &dyn RuntimeBackend) {
    ev.extra.insert(
        "metadata".to_string(),
        serde_json::to_value(backend.metadata()).unwrap_or(Value::Null),
    );

    let t0 = Instant::now();
    match backend.prepare(&live_sandbox_config(&ev.sandbox_id)).await {
        Ok(prepared) => ev.phase(
            "prepare",
            true,
            elapsed_ms(&t0),
            Some(format!("receipts={:?}", prepared.resources)),
        ),
        Err(e) => abort_walk(ev, backend, "prepare", e.to_string()).await,
    }

    let t0 = Instant::now();
    if let Err(e) = backend.boot().await {
        abort_walk(ev, backend, "boot", e.to_string()).await;
    }
    ev.phase("boot", true, elapsed_ms(&t0), None);
    check_state(ev, backend, "state_after_boot", SandboxState::Running).await;

    let t0 = Instant::now();
    let transport = match backend.attach_transport().await {
        Ok(t) => {
            ev.phase("attach_transport", true, elapsed_ms(&t0), None);
            t
        }
        Err(e) => abort_walk(ev, backend, "attach_transport", e.to_string()).await,
    };
    if !matches!(&transport, GuestTransport::Unix { .. }) {
        abort_walk(
            ev,
            backend,
            "attach_transport",
            format!("gVisor attach must be Unix, got {transport:?}"),
        )
        .await;
    }
    ev.extra.insert(
        "transport".to_string(),
        serde_json::json!({
            "expected": "unix",
            "observed": serde_json::to_value(&transport).unwrap_or(Value::Null),
            "production_ok": true,
        }),
    );

    // gVisor declares no GuestReadiness capability; there is no wait_ready
    // handshake on this path. Exec via `runsc exec` is the liveness proof.
    ev.phase_skipped(
        "wait_ready",
        "skipped: gVisor declares no GuestReadiness capability; runsc-exec probes below are the liveness proof",
    );

    run_exec_probes(ev, backend).await;
    run_observability(ev, backend).await;

    // Suspend/Resume/Fork are undeclared for gVisor. Probe that they stay
    // Unsupported (contract pin, informational only).
    let suspend_outcome = match backend.suspend().await {
        Err(pico_core::BackendError::Unsupported { .. }) => "unsupported-as-declared",
        Err(e) => {
            ev.phase(
                "suspend_unsupported_probe",
                true,
                0,
                Some(format!(
                    "non-Unsupported error (contract drift, informational): {e}"
                )),
            );
            "error-informational"
        }
        Ok(()) => {
            ev.phase(
                "suspend_unsupported_probe",
                true,
                0,
                Some("suspend succeeded (contract drift, informational)".to_string()),
            );
            "ok-informational"
        }
    };
    if suspend_outcome == "unsupported-as-declared" {
        ev.phase(
            "suspend_unsupported_probe",
            true,
            0,
            Some("suspend returns Unsupported as declared".to_string()),
        );
    }
    ev.phase_skipped(
        "suspend_resume",
        "skipped: gVisor declares no Suspend/Resume capability",
    );
    ev.extra.insert(
        "suspend_resume".to_string(),
        serde_json::json!({"attempted": false, "reason": "capability-undeclared"}),
    );

    destroy_and_cleanup(ev, backend).await;
    ev.finish("pass", None);
}

// ---------------------------------------------------------------------------
// Shared walk stages
// ---------------------------------------------------------------------------

/// Maximum time to wait for the guest agent TCP after the vsock attach.
/// Slow hosts (nested virtualization needs tens of seconds for guest boot)
/// must not fail fast here: unreachable means "not up yet" until the
/// deadline, and fail-closed after it.
const GUEST_TCP_WAIT_SECS: u64 = 240;

/// Polls the TAP-routed guest-agent TCP until it accepts connections or the
/// deadline expires. Adapter `wait_ready` is accept-only for vsock, so
/// without this wait the exec probes would race guest boot and mistake a
/// slow host for a broken guest (live-boot finding on nested KVM).
async fn wait_for_guest_tcp(ev: &mut Evidence, backend: &dyn RuntimeBackend) {
    let cfg = pico_runtime::firecracker::config::FirecrackerConfig::detect_defaults();
    let network = pico_runtime::firecracker::config::NetworkConfig::for_sandbox_id(&ev.sandbox_id);
    let addr = SocketAddr::new(network.guest_ip.into(), cfg.guest_agent_addr.port());
    let deadline = Duration::from_secs(GUEST_TCP_WAIT_SECS);
    let t0 = Instant::now();
    loop {
        match tokio::time::timeout(Duration::from_secs(2), tokio::net::TcpStream::connect(addr))
            .await
        {
            Ok(Ok(_)) => {
                ev.phase(
                    "wait_guest_agent",
                    true,
                    elapsed_ms(&t0),
                    Some(format!("guest agent TCP {addr} reachable")),
                );
                return;
            }
            Ok(Err(_)) | Err(_) => {
                if t0.elapsed() >= deadline {
                    abort_walk(
                        ev,
                        backend,
                        "wait_guest_agent",
                        format!(
                            "guest agent TCP {addr} unreachable after {}s",
                            deadline.as_secs()
                        ),
                    )
                    .await;
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }
}

async fn run_exec_probes(ev: &mut Evidence, backend: &dyn RuntimeBackend) {
    let t0 = Instant::now();
    match backend.exec(exec_request("true", &[])).await {
        Ok(resp) if resp.exit_code == 0 => {
            ev.phase("exec_true", true, elapsed_ms(&t0), None);
        }
        Ok(resp) => {
            abort_walk(
                ev,
                backend,
                "exec_true",
                format!("exit={} stderr={:?}", resp.exit_code, resp.stderr),
            )
            .await;
        }
        Err(e) => abort_walk(ev, backend, "exec_true", e.to_string()).await,
    }

    let t0 = Instant::now();
    match backend
        .exec(exec_request("printf", &["pico-live-boot"]))
        .await
    {
        Ok(resp) if resp.exit_code == 0 && resp.stdout == "pico-live-boot" => {
            ev.extra.insert(
                "exec".to_string(),
                serde_json::json!({
                    "command": "printf pico-live-boot",
                    "exit_code": resp.exit_code,
                    "stdout": resp.stdout,
                    "stderr": resp.stderr,
                    "duration_ms": resp.duration_ms,
                }),
            );
            ev.phase("exec_printf", true, elapsed_ms(&t0), None);
        }
        Ok(resp) => {
            abort_walk(
                ev,
                backend,
                "exec_printf",
                format!(
                    "exit={} stdout={:?} stderr={:?}",
                    resp.exit_code, resp.stdout, resp.stderr
                ),
            )
            .await;
        }
        Err(e) => abort_walk(ev, backend, "exec_printf", e.to_string()).await,
    }
}

async fn run_observability(ev: &mut Evidence, backend: &dyn RuntimeBackend) {
    let t0 = Instant::now();
    match backend.stats().await {
        Ok(stats) => {
            ev.extra.insert(
                "stats".to_string(),
                serde_json::to_value(&stats).unwrap_or(Value::Null),
            );
            ev.phase("stats", true, elapsed_ms(&t0), None);
        }
        Err(e) => abort_walk(ev, backend, "stats", e.to_string()).await,
    }

    let t0 = Instant::now();
    match backend.health().await {
        Ok(health) => {
            ev.extra.insert(
                "health".to_string(),
                serde_json::to_value(&health).unwrap_or(Value::Null),
            );
            if health.status == pico_core::BackendHealthStatus::Ready {
                ev.phase("health", true, elapsed_ms(&t0), health.message);
            } else {
                abort_walk(
                    ev,
                    backend,
                    "health",
                    format!("status={:?} message={:?}", health.status, health.message),
                )
                .await;
            }
        }
        Err(e) => abort_walk(ev, backend, "health", e.to_string()).await,
    }

    let t0 = Instant::now();
    match backend.diagnostics().await {
        Ok(bundle) => {
            ev.extra.insert(
                "diagnostics".to_string(),
                serde_json::json!({
                    "captured_at": bundle.captured_at,
                    "summary": bundle.summary,
                    "artifacts": bundle.artifacts,
                }),
            );
            ev.collect_tails(&bundle.artifacts);
            ev.phase("diagnostics", true, elapsed_ms(&t0), None);
        }
        Err(e) => abort_walk(ev, backend, "diagnostics", e.to_string()).await,
    }
}

async fn destroy_and_cleanup(ev: &mut Evidence, backend: &dyn RuntimeBackend) {
    let t0 = Instant::now();
    match backend.destroy().await {
        Ok(report) => {
            if report.remaining.is_empty() {
                ev.phase(
                    "destroy",
                    true,
                    elapsed_ms(&t0),
                    Some(format!("released={:?}", report.released)),
                );
            } else {
                abort_walk(
                    ev,
                    backend,
                    "destroy",
                    format!("leftover resources: {:?}", report.remaining),
                )
                .await;
            }
        }
        Err(e) => abort_walk(ev, backend, "destroy", e.to_string()).await,
    }
    check_state(ev, backend, "state_after_destroy", SandboxState::Destroyed).await;

    let t0 = Instant::now();
    match backend.cleanup().await {
        Ok(_) => ev.phase("cleanup", true, elapsed_ms(&t0), None),
        Err(e) => abort_walk(ev, backend, "cleanup", e.to_string()).await,
    }
    check_state(ev, backend, "state_after_cleanup", SandboxState::Destroyed).await;
}

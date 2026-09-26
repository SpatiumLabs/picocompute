//! Runs the in-guest command execution service used by PicoCompute runtimes.
//!
//! Single wire format: every connection is a framed-protobuf bootstrap
//! handshake followed by the operational protocol on the same stream.
//! The legacy JSON-RPC 2.0 path has been removed.

mod context;
mod control;
mod exec;
mod file;
mod handshake;
mod health;
mod mount;
mod secrets;
mod shutdown;
mod stats;

use std::time::Duration;

use tokio::net::TcpListener;

use pico_guest_protocol::FramedConnection;

use crate::exec::BoxGuestStream;

const OPERATIONAL_TIMEOUT_SECS: u64 = 300;

/// Unix socket path for guest listen mode, from `PICO_GUEST_AGENT_SOCKET`.
///
/// When set, the agent binds a Unix domain socket instead of TCP. Unix is
/// the production guest transport for container and gVisor backends, which
/// receive a permission-controlled socket rather than a TCP listener.
fn read_listen_socket() -> Option<String> {
    std::env::var("PICO_GUEST_AGENT_SOCKET")
        .ok()
        .filter(|v| !v.trim().is_empty())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing::info!("Guest Agent starting...");

    pico_guest_agent_init_seccomp();

    let identity = load_identity().unwrap_or_default();
    let sandbox_id = read_sandbox_id().unwrap_or_else(|| "unknown-sandbox".into());
    let shared_secret = pico_core::crypto::derive_handshake_shared_secret(&sandbox_id);
    let listen_port = read_listen_port();

    tracing::info!(
        image_id = %identity.image_id,
        boot_id = %identity.boot_id,
        sandbox_id = %sandbox_id,
        agent_version = %identity.agent_version,
        "guest agent initialized"
    );

    if let Some(socket_path) = read_listen_socket() {
        serve_unix_listener(&socket_path, &identity, &shared_secret, &sandbox_id).await?;
        return Ok(());
    }

    let listener = TcpListener::bind(("0.0.0.0", listen_port)).await?;
    tracing::info!("Listening for host connections on port {listen_port}");

    loop {
        let (socket, peer_addr) = listener.accept().await?;
        tracing::debug!(peer = %peer_addr, "new TCP connection");
        serve_stream(
            Box::new(socket),
            identity.clone(),
            shared_secret.clone(),
            sandbox_id.clone(),
        );
    }
}

async fn serve_unix_listener(
    path: &str,
    identity: &handshake::GuestIdentity,
    shared_secret: &heapless::Vec<u8, 32>,
    sandbox_id: &str,
) -> anyhow::Result<()> {
    if std::fs::remove_file(path).is_ok() {
        tracing::info!(path = %path, "removed stale guest socket");
    }
    let listener = tokio::net::UnixListener::bind(path)?;
    tracing::info!(path = %path, "Listening for host connections on unix socket");

    loop {
        let (socket, _) = listener.accept().await?;
        tracing::debug!("new unix connection");
        serve_stream(
            Box::new(socket),
            identity.clone(),
            shared_secret.clone(),
            sandbox_id.to_string(),
        );
    }
}

fn serve_stream(
    socket: BoxGuestStream,
    identity: handshake::GuestIdentity,
    shared_secret: heapless::Vec<u8, 32>,
    sandbox_id: String,
) {
    tokio::spawn(async move {
        handle_handshake_connection(socket, &identity, &shared_secret, &sandbox_id).await;
    });
}

async fn handle_handshake_connection(
    mut socket: BoxGuestStream,
    identity: &handshake::GuestIdentity,
    shared_secret: &heapless::Vec<u8, 32>,
    sandbox_id: &str,
) {
    match handshake::serve_handshake(&mut socket, identity, shared_secret.clone()).await {
        Ok(Some(outcome)) => {
            tracing::info!(
                boot_id = %identity.boot_id,
                sandbox_id = %sandbox_id,
                "handshake completed, entering operational mode"
            );

            let session = exec::OperationalSession::new(&outcome, sandbox_id.to_string());
            let conn = FramedConnection::new(socket, Duration::from_secs(OPERATIONAL_TIMEOUT_SECS));
            exec::serve_operational(conn, session).await;
        }
        Ok(None) => {
            tracing::warn!("handshake rejected by guest");
        }
        Err(err) => {
            tracing::error!(error = %err, "handshake failed");
        }
    }
}

fn load_identity() -> Option<handshake::GuestIdentity> {
    let manifest_paths = [
        "/etc/pico/manifest.json",
        "/opt/pico/manifest.json",
        "/pico/manifest.json",
    ];

    for path in &manifest_paths {
        if let Ok(content) = std::fs::read_to_string(path) {
            tracing::info!(path = %path, "loaded image manifest");
            return handshake::parse_manifest_json(&content);
        }
    }

    tracing::warn!("no image manifest found, using default identity");
    None
}

fn read_sandbox_id() -> Option<String> {
    // Kernel cmdline is the boot-time authority supplied by the hypervisor;
    // environment is only a test escape hatch for host-process testing. Checking
    // cmdline first prevents a compromised guest environment from overriding the
    // hypervisor-provided identity.
    if let Ok(cmdline) = std::fs::read_to_string("/proc/cmdline")
        && let Some(id) = handshake::parse_sandbox_id_from_cmdline(&cmdline)
    {
        tracing::info!(sandbox_id = %id, "read sandbox_id from kernel cmdline");
        return Some(id);
    }

    if let Ok(id) = std::env::var("PICO_SANDBOX_ID")
        && !id.trim().is_empty()
    {
        tracing::info!(sandbox_id = %id, "read sandbox_id from PICO_SANDBOX_ID");
        return Some(id.trim().to_string());
    }

    tracing::warn!("no sandbox_id found in /proc/cmdline or PICO_SANDBOX_ID");
    None
}

fn read_listen_port() -> u16 {
    std::env::var("PICO_GUEST_AGENT_PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(9999)
}

fn pico_guest_agent_init_seccomp() {
    use pico_seccomp::{CapabilitySet, ComponentProfile};
    use tracing::info;

    info!("initializing seccomp and capability minimization for guest-agent");

    let _ = pico_seccomp::init_profile_for_component_with_strictness(
        ComponentProfile::GuestAgent,
        &CapabilitySet::guest_agent(),
        true,
        false,
    );
}

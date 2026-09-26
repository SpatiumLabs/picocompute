//! UDS bind helpers and tonic server entrypoint.

use std::path::Path;

use anyhow::{Context, Result, bail};
use pico_sandboxd_proto::v1::sandboxd_server::SandboxdServer;
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::Server;
use tracing::info;

use super::auth::AuthInterceptor;
use super::service::SandboxdService;
use crate::config::SandboxdConfig;
use crate::registry::AdapterRegistry;
use crate::{HostResourceConfig, NetworkAttachManager, SandboxSupervisor};

/// Binds a Unix listener at `socket_path`, replacing any stale socket file.
///
/// Parent directories are created when missing. Mode is set to `0o660` when the
/// platform supports unix permissions.
///
/// # Errors
///
/// Returns an error when the socket path cannot be prepared or bound.
pub async fn bind_uds(socket_path: &Path) -> Result<UnixListener> {
    if let Some(parent) = socket_path.parent()
        && !parent.as_os_str().is_empty()
    {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("create socket parent {}", parent.display()))?;
    }
    if socket_path.exists() {
        use std::os::unix::fs::FileTypeExt;
        let meta = tokio::fs::symlink_metadata(socket_path)
            .await
            .with_context(|| format!("stat {}", socket_path.display()))?;
        if !meta.file_type().is_socket() {
            bail!(
                "path {} exists and is not a socket; refusing to remove",
                socket_path.display()
            );
        }
        tokio::fs::remove_file(socket_path)
            .await
            .with_context(|| format!("remove stale socket {}", socket_path.display()))?;
    }

    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("bind sandboxd socket {}", socket_path.display()))?;

    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let fd = listener.as_raw_fd();
        let ret = unsafe { libc::fchmod(fd, 0o660) };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            return Err(err).with_context(|| format!("fchmod socket {}", socket_path.display()));
        }
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o660))
            .with_context(|| format!("chmod socket {}", socket_path.display()))?;
    }

    Ok(listener)
}

/// Serves the sandboxd gRPC API on an already-bound Unix listener until
/// `shutdown` completes.
///
/// # Errors
///
/// Returns an error when the tonic server fails.
pub async fn serve_uds(
    listener: UnixListener,
    supervisor: SandboxSupervisor,
    registry: AdapterRegistry,
    config: &SandboxdConfig,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<()> {
    let auth = AuthInterceptor::new(config.auth_token.clone(), config.allowed_peer_uids.clone());
    let service = SandboxdService::new(supervisor, registry);
    let incoming = UnixListenerStream::new(listener);

    info!("sandboxd gRPC serving on UDS");
    Server::builder()
        .add_service(SandboxdServer::with_interceptor(service, auth))
        .serve_with_incoming_shutdown(incoming, shutdown)
        .await
        .context("sandboxd gRPC server error")?;
    Ok(())
}

/// Opens the ledger, reconciles interrupted ops, and serves until shutdown.
///
/// # Errors
///
/// Returns an error when ledger open, reconcile, bind, or serve fails.
pub async fn run(
    config: SandboxdConfig,
    registry: AdapterRegistry,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<()> {
    let supervisor = SandboxSupervisor::open(
        &config.ledger_path,
        HostResourceConfig::new(config.workspace_root.clone())
            .with_cpu_isolation_policy(config.cpu_isolation_policy)
            .with_cross_tenant_host(config.cross_tenant_host),
    )
    .with_context(|| format!("open ledger {}", config.ledger_path.display()))?
    .with_dns_listen_addr(config.dns_proxy_listen_addr)
    .with_network(std::sync::Arc::new(if config.network_enabled {
        NetworkAttachManager::new()
    } else {
        info!("sandboxd network provisioning disabled (PICO_SANDBOXD_NETWORK=disabled)");
        NetworkAttachManager::disabled()
    }));
    let marked = supervisor
        .reconcile()
        .await
        .context("reconcile interrupted operations")?;
    info!(marked, "sandboxd reconcile complete");

    let gc = supervisor.create_gc();
    tokio::spawn(async move {
        gc.run().await;
    });

    let listener = bind_uds(&config.socket_path).await?;
    info!(socket = %config.socket_path.display(), "sandboxd listening");
    serve_uds(listener, supervisor, registry, &config, shutdown).await
}

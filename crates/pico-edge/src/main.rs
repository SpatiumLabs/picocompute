//! PicoCompute edge gateway — main entry point.
//!
//! A Pingora-based HTTP/WebSocket proxy that validates PicoCompute access leases
//! before forwarding traffic to sandbox TCP backends.

use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use pico_core::{Hlc, InMemoryAuditSink, LeaseAuthority, LeaseManager};
use pico_edge::config::{CliArgs, EdgeConfig};
use pico_edge::proxy::EdgeProxy;
use pico_edge::routing::{RoutingTable, Upstream};
use pingora_core::listeners::tls::TlsSettings;
use pingora_core::server::Server;
use pingora_proxy::http_proxy_service;
use tracing_subscriber::EnvFilter;

fn main() -> anyhow::Result<()> {
    let cli = CliArgs::parse();

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // Load configuration
    let config =
        EdgeConfig::load(cli.config.clone(), &cli).context("failed to load configuration")?;

    tracing::info!(
        listen_addr = %config.listen_addr,
        default_upstream = %config.default_upstream,
        require_lease = config.require_lease,
        "pico-edge starting"
    );

    // Set up core components.
    //
    // TODO: make the audit sink configurable (e.g., ChannelAuditSink or
    // PostgresAuditSink from pico-core) through a config enum or feature
    // flag. InMemoryAuditSink is fine for development but buffers are lost
    // on restart and have no multi-process visibility.
    let lease_manager = Arc::new(LeaseManager::new());
    let audit_sink: Arc<dyn pico_core::AuditEventSink> = Arc::new(InMemoryAuditSink::new());
    let hlc = Arc::new(Hlc::new());

    // Set up routing table
    let routing_table = Arc::new(RoutingTable::new(Upstream::tcp(&config.default_upstream)));

    // Build the edge proxy.
    let mut proxy = EdgeProxy::new(
        lease_manager,
        routing_table,
        audit_sink,
        hlc,
        config.policy_epoch,
        config.require_lease,
        config.default_endpoint_max_rps,
        config.default_endpoint_max_connections,
    );
    if let Ok(encoded) = std::env::var("PICO_LEASE_VERIFYING_KEY")
        && !encoded.is_empty()
    {
        let authority = LeaseAuthority::from_verifying_key_base64(&encoded)
            .map_err(|e| anyhow::anyhow!("PICO_LEASE_VERIFYING_KEY: {e}"))?;
        proxy = proxy.with_lease_authority(authority);
        tracing::info!("lease blob verification enabled");
    } else if config.require_lease {
        tracing::warn!("PICO_LEASE_VERIFYING_KEY unset; signed lease blobs cannot be verified");
    }

    // Build the Pingora server.
    let mut server = Server::new(None)?;
    server.bootstrap();

    // Register the HTTP proxy service with both TCP and optional TLS listeners.
    let mut proxy_service = http_proxy_service(&server.configuration, proxy);
    proxy_service.add_tcp(&config.listen_addr.to_string());

    if let (Some(tls_addr), Some(tls_cert), Some(tls_key)) =
        (config.listen_addr_tls, &config.tls_cert, &config.tls_key)
    {
        let cert_path = tls_cert.to_str().context("invalid TLS cert path")?;
        let key_path = tls_key.to_str().context("invalid TLS key path")?;

        tracing::info!(listen_addr_tls = %tls_addr, "TLS enabled");
        let tls_settings = TlsSettings::intermediate(cert_path, key_path)
            .context("failed to create TLS settings")?;
        proxy_service.add_tls_with_settings(&tls_addr.to_string(), None, tls_settings);
    }

    server.add_service(proxy_service);
    // run_forever handles graceful reload internally via Pingora's native
    // upgrade-socket protocol. Sending SIGHUP or using the upgrade socket
    // triggers a zero-downtime restart that drains existing connections
    // (including WebSocket streams) before the new process takes over.
    server.run_forever();

    // run_forever never returns; the following is for documentation clarity
    #[expect(unreachable_code, reason = "run_forever never returns")]
    Ok(())
}

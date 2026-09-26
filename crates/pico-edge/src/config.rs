//! Configuration for pico-edge.

use clap::Parser;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

/// PicoCompute edge gateway configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeConfig {
    /// Address the edge gateway listens on for HTTP.
    pub listen_addr: SocketAddr,
    /// Address the edge gateway listens on for HTTPS (TLS).
    #[serde(default)]
    pub listen_addr_tls: Option<SocketAddr>,
    /// Path to TLS certificate (PEM).
    #[serde(default)]
    pub tls_cert: Option<PathBuf>,
    /// Path to TLS private key (PEM).
    #[serde(default)]
    pub tls_key: Option<PathBuf>,
    /// Default upstream host-agent address (host:port).
    pub default_upstream: String,
    /// Per-request lease validation: if true, every proxied request must carry
    /// a valid lease. If false, leases are validated only when the upstream
    /// endpoint requires them.
    #[serde(default = "default_require_lease")]
    pub require_lease: bool,
    /// Maximum number of concurrent connections.
    #[serde(default)]
    pub max_connections: Option<usize>,
    /// Per-endpoint default connection limit.
    #[serde(default)]
    pub default_endpoint_max_connections: Option<usize>,
    /// Per-endpoint default requests-per-second limit.
    #[serde(default)]
    pub default_endpoint_max_rps: Option<u32>,
    /// Number of worker threads for the Pingora server.
    #[serde(default)]
    pub workers: Option<usize>,
    /// Path to a TOML configuration file.
    #[serde(default)]
    pub config_file: Option<PathBuf>,
    /// Current policy epoch for lease validation.
    #[serde(default)]
    pub policy_epoch: u64,
}

impl Default for EdgeConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:8080".parse().unwrap(),
            listen_addr_tls: None,
            tls_cert: None,
            tls_key: None,
            default_upstream: "127.0.0.1:9000".to_string(),
            require_lease: true,
            max_connections: None,
            default_endpoint_max_connections: None,
            default_endpoint_max_rps: None,
            workers: None,
            config_file: None,
            policy_epoch: 0,
        }
    }
}

fn default_require_lease() -> bool {
    true
}

impl EdgeConfig {
    /// Load configuration from a TOML file and merge with CLI args.
    pub fn load(config_file: Option<PathBuf>, cli: &CliArgs) -> Result<Self, anyhow::Error> {
        let mut config = if let Some(ref path) = config_file {
            let contents = std::fs::read_to_string(path)?;
            toml::from_str(&contents)?
        } else {
            Self::default()
        };

        // Override with CLI args
        if let Some(addr) = cli.listen {
            config.listen_addr = addr;
        }
        if let Some(addr) = cli.listen_tls {
            config.listen_addr_tls = Some(addr);
        }
        if let Some(ref cert) = cli.tls_cert {
            config.tls_cert = Some(cert.clone());
        }
        if let Some(ref key) = cli.tls_key {
            config.tls_key = Some(key.clone());
        }
        if let Some(ref upstream) = cli.upstream {
            config.default_upstream = upstream.clone();
        }
        if cli.no_lease_check {
            config.require_lease = false;
        }
        if let Some(workers) = cli.workers {
            config.workers = Some(workers);
        }
        if let Some(max_conns) = cli.max_connections {
            config.max_connections = Some(max_conns);
        }
        config.config_file = config_file;

        Ok(config)
    }
}

/// Command-line arguments for pico-edge.
#[derive(Parser, Debug, Clone)]
#[command(name = "pico-edge", version, about = "PicoCompute edge gateway")]
pub struct CliArgs {
    /// Address to listen on for HTTP (e.g., 0.0.0.0:8080).
    #[arg(long, short = 'l')]
    pub listen: Option<SocketAddr>,

    /// Address to listen on for HTTPS/TLS.
    #[arg(long)]
    pub listen_tls: Option<SocketAddr>,

    /// Path to TLS certificate (PEM).
    #[arg(long)]
    pub tls_cert: Option<PathBuf>,

    /// Path to TLS private key (PEM).
    #[arg(long)]
    pub tls_key: Option<PathBuf>,

    /// Default upstream host-agent address (host:port).
    #[arg(long, short = 'u', default_value = "127.0.0.1:9000")]
    pub upstream: Option<String>,

    /// Disable lease validation for proxied requests (development only).
    #[arg(long)]
    pub no_lease_check: bool,

    /// Number of worker threads.
    #[arg(long, short = 'w')]
    pub workers: Option<usize>,

    /// Maximum number of concurrent connections.
    #[arg(long)]
    pub max_connections: Option<usize>,

    /// Path to TOML configuration file.
    #[arg(long, short = 'c')]
    pub config: Option<PathBuf>,
}

//! sandboxd process configuration (file + environment overrides).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

use pico_core::cpu_isolation::CpuIsolationPolicy;
use serde::{Deserialize, Serialize};

/// Log encoding selected at process start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum LogFormat {
    /// Human-readable tracing output.
    #[default]
    Pretty,
    /// Structured JSON logs.
    Json,
}

/// Runtime configuration for the sandboxd OS process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxdConfig {
    /// Unix domain socket path for the gRPC control plane.
    #[serde(default = "default_socket_path")]
    pub socket_path: PathBuf,
    /// Shared host-agent <-> sandboxd auth token (metadata key
    /// `x-pico-sandboxd-token`).
    #[serde(default)]
    pub auth_token: String,
    /// Durable SQLite ledger path.
    #[serde(default = "default_ledger_path")]
    pub ledger_path: PathBuf,
    /// Workspace root for per-sandbox directories and garbage collection.
    #[serde(default = "default_workspace_root")]
    pub workspace_root: PathBuf,
    /// CPU isolation policy enforced while materializing per-sandbox cgroups
    /// and cpuset pinning during prepare.
    #[serde(default)]
    pub cpu_isolation_policy: CpuIsolationPolicy,
    /// Whether this host mixes tenants. When true, CPU allocation failures
    /// hard-fail prepare regardless of the per-request flag, so a request can
    /// never weaken the daemon's isolation contract.
    #[serde(default)]
    pub cross_tenant_host: bool,
    /// UIDs allowed via `SO_PEERCRED`. Empty means any peer UID is accepted
    /// (token auth still required).
    #[serde(default)]
    pub allowed_peer_uids: Vec<u32>,
    /// Tracing log format.
    #[serde(default)]
    pub log_format: LogFormat,
    /// Optional DNS proxy listen address. When set, sandboxd owns the DNS
    /// policy proxy process and attaches per-sandbox DNS redirects on boot.
    #[serde(default)]
    pub dns_proxy_listen_addr: Option<SocketAddr>,
    /// Whether to perform kernel-level network provisioning (TAP/veth).
    /// Set to false in test environments without CAP_NET_ADMIN.
    #[serde(default = "default_true")]
    pub network_enabled: bool,
}

fn default_socket_path() -> PathBuf {
    PathBuf::from("/var/run/pico/sandboxd.sock")
}

fn default_ledger_path() -> PathBuf {
    PathBuf::from("/var/lib/pico/sandboxd/state.db")
}

fn default_workspace_root() -> PathBuf {
    PathBuf::from("/var/lib/pico/workspaces")
}

fn default_true() -> bool {
    true
}

impl Default for SandboxdConfig {
    fn default() -> Self {
        Self {
            socket_path: default_socket_path(),
            auth_token: String::new(),
            ledger_path: default_ledger_path(),
            workspace_root: default_workspace_root(),
            cpu_isolation_policy: CpuIsolationPolicy::default(),
            cross_tenant_host: false,
            allowed_peer_uids: Vec::new(),
            log_format: LogFormat::Pretty,
            dns_proxy_listen_addr: None,
            network_enabled: true,
        }
    }
}

impl SandboxdConfig {
    /// Load config from `PICO_SANDBOXD_CONFIG` (default
    /// `/etc/pico/sandboxd.toml`) and apply environment overrides.
    ///
    /// # Errors
    ///
    /// Returns an error when the config file is present but invalid, or when
    /// required fields are missing after env overrides.
    pub fn from_file_or_env() -> anyhow::Result<Self> {
        let config_path = std::env::var("PICO_SANDBOXD_CONFIG")
            .unwrap_or_else(|_| "/etc/pico/sandboxd.toml".into());

        let mut config = if let Ok(content) = std::fs::read_to_string(&config_path) {
            toml::from_str::<Self>(&content)
                .map_err(|err| anyhow::anyhow!("invalid config file {config_path}: {err}"))?
        } else {
            Self::default()
        };

        apply_env_overrides(&mut config)?;
        ensure_valid(&config)?;
        Ok(config)
    }
}

/// Parses the `PICO_SANDBOXD_CPU_ISOLATION_POLICY` environment value.
///
/// Unknown values are rejected instead of silently downgrading tenant
/// isolation.
fn parse_cpu_isolation_policy(value: &str) -> anyhow::Result<CpuIsolationPolicy> {
    match value {
        "dedicated-cores-with-smt-exclusion" => {
            Ok(CpuIsolationPolicy::DedicatedCoresWithSmtExclusion)
        }
        "dedicated-cores" => Ok(CpuIsolationPolicy::DedicatedCores),
        "none" => Ok(CpuIsolationPolicy::None),
        other => anyhow::bail!(
            "unrecognized PICO_SANDBOXD_CPU_ISOLATION_POLICY '{other}' \
             (expected none|dedicated-cores|dedicated-cores-with-smt-exclusion)"
        ),
    }
}

fn apply_env_overrides(config: &mut SandboxdConfig) -> anyhow::Result<()> {
    if let Ok(val) = std::env::var("PICO_SANDBOXD_SOCKET")
        && !val.is_empty()
    {
        config.socket_path = PathBuf::from(val);
    }
    if let Ok(val) = std::env::var("PICO_SANDBOXD_TOKEN")
        && !val.is_empty()
    {
        config.auth_token = val;
    }
    if let Ok(val) = std::env::var("PICO_SANDBOXD_STATE_PATH")
        && !val.is_empty()
    {
        config.ledger_path = PathBuf::from(val);
    }
    if let Ok(val) = std::env::var("PICO_WORKSPACE_ROOT")
        && !val.is_empty()
    {
        config.workspace_root = PathBuf::from(val);
    }
    if let Ok(val) = std::env::var("PICO_SANDBOXD_CPU_ISOLATION_POLICY") {
        config.cpu_isolation_policy = parse_cpu_isolation_policy(&val)?;
    }
    if let Ok(val) = std::env::var("PICO_SANDBOXD_CROSS_TENANT_HOST") {
        config.cross_tenant_host = val.eq_ignore_ascii_case("true") || val == "1";
    }
    if let Ok(val) = std::env::var("PICO_SANDBOXD_ALLOWED_PEER_UIDS")
        && !val.is_empty()
    {
        config.allowed_peer_uids = val
            .split(',')
            .filter_map(|part| {
                let trimmed = part.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    u32::from_str(trimmed).ok()
                }
            })
            .collect();
    }
    if let Ok(val) = std::env::var("PICO_LOG_FORMAT") {
        config.log_format = match val.as_str() {
            "json" => LogFormat::Json,
            _ => LogFormat::Pretty,
        };
    }
    if let Ok(val) = std::env::var("PICO_SANDBOXD_DNS_PROXY_LISTEN")
        && !val.is_empty()
    {
        config.dns_proxy_listen_addr = Some(
            SocketAddr::from_str(&val)
                .map_err(|err| anyhow::anyhow!("invalid PICO_SANDBOXD_DNS_PROXY_LISTEN: {err}"))?,
        );
    }
    if let Ok(val) = std::env::var("PICO_SANDBOXD_NETWORK") {
        config.network_enabled = !val.eq_ignore_ascii_case("disabled")
            && !val.eq_ignore_ascii_case("false")
            && val != "0";
    }
    Ok(())
}

fn ensure_valid(config: &SandboxdConfig) -> anyhow::Result<()> {
    if config.auth_token.is_empty() {
        anyhow::bail!("sandboxd auth_token is required (set PICO_SANDBOXD_TOKEN)");
    }
    if config.socket_path.as_os_str().is_empty() {
        anyhow::bail!("sandboxd socket_path must not be empty");
    }
    if config.ledger_path.as_os_str().is_empty() {
        anyhow::bail!("sandboxd ledger_path must not be empty");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_token() {
        let config = SandboxdConfig::default();
        assert!(ensure_valid(&config).is_err());
    }

    #[test]
    fn accepts_token() {
        let config = SandboxdConfig {
            auth_token: "secret".into(),
            ..Default::default()
        };
        assert!(ensure_valid(&config).is_ok());
    }

    #[test]
    fn parses_known_cpu_isolation_policies() {
        assert_eq!(
            parse_cpu_isolation_policy("dedicated-cores").unwrap(),
            CpuIsolationPolicy::DedicatedCores
        );
        assert_eq!(
            parse_cpu_isolation_policy("dedicated-cores-with-smt-exclusion").unwrap(),
            CpuIsolationPolicy::DedicatedCoresWithSmtExclusion
        );
        assert_eq!(
            parse_cpu_isolation_policy("none").unwrap(),
            CpuIsolationPolicy::None
        );
    }

    #[test]
    fn rejects_unknown_cpu_isolation_policy() {
        assert!(parse_cpu_isolation_policy("dedicated").is_err());
    }
}

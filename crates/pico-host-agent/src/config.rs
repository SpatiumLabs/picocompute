//! Host-agent configuration via file and environment-variable overrides.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

use pico_core::RuntimeType;
use pico_core::cpu_isolation::CpuIsolationPolicy;
use serde::{Deserialize, Serialize};

use crate::identity::HostIdentity;

use zeroize::Zeroizing;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostAgentConfig {
    pub bind_addr: SocketAddr,
    /// Host-agent API auth token. Never serialized: the config is only read
    /// from disk, and a serialized dump would leak the credential.
    #[serde(default, skip_serializing)]
    pub auth_token: Zeroizing<String>,
    pub workspace_root: PathBuf,
    /// Unix domain socket path for the sandboxd control plane.
    #[serde(default = "default_sandboxd_socket_path")]
    pub sandboxd_socket_path: PathBuf,
    /// Shared host-agent <-> sandboxd auth token (`x-pico-sandboxd-token`).
    /// Zeroized on drop. Never serialized.
    #[serde(default, skip_serializing)]
    pub sandboxd_token: Zeroizing<String>,
    pub idle_timeout_secs: u64,
    pub default_runtime: RuntimeType,
    pub identity: HostIdentity,
    pub drain_timeout_secs: u64,
    pub log_format: LogFormat,

    /// CPU isolation policy for this host.
    /// - `none`: No CPU pinning. All sandboxes share all CPUs.
    /// - `dedicated-cores`: Per-sandbox CPU pinning with non-overlapping sets.
    /// - `dedicated-cores-with-smt-exclusion`: Dedicated cores plus SMT
    ///   sibling exclusion across sandboxes from different tenants.
    #[serde(default)]
    pub cpu_isolation_policy: CpuIsolationPolicy,

    /// Whether this host accepts cross-tenant sandbox placement.
    /// When true, CPU isolation policy is enforced against all backends.
    #[serde(default)]
    pub cross_tenant_host: bool,

    /// When enabled on multi-tenant hosts, replaces per-sandbox metric
    /// labels (sandbox_id) with tenant-level labels, buckets lifecycle
    /// timing per tenant, rate-limits network interface counters, and
    /// excludes per-sandbox cgroup event metrics.
    #[serde(default)]
    pub shared_host_metric_redaction: bool,

    #[serde(skip)]
    pub draining: bool,
}

// Manual Debug impl (no derived): both auth tokens are redacted below. Keep
// every new field in sync here so future fields cannot silently vanish from
// debug output (or worse, leak a secret).
impl std::fmt::Debug for HostAgentConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostAgentConfig")
            .field("bind_addr", &self.bind_addr)
            .field("auth_token", &"[REDACTED]")
            .field("workspace_root", &self.workspace_root)
            .field("sandboxd_socket_path", &self.sandboxd_socket_path)
            .field("sandboxd_token", &"[REDACTED]")
            .field("idle_timeout_secs", &self.idle_timeout_secs)
            .field("default_runtime", &self.default_runtime)
            .field("identity", &self.identity)
            .field("drain_timeout_secs", &self.drain_timeout_secs)
            .field("log_format", &self.log_format)
            .field("cpu_isolation_policy", &self.cpu_isolation_policy)
            .field("cross_tenant_host", &self.cross_tenant_host)
            .field(
                "shared_host_metric_redaction",
                &self.shared_host_metric_redaction,
            )
            .field("draining", &self.draining)
            .finish()
    }
}

fn default_sandboxd_socket_path() -> PathBuf {
    PathBuf::from(crate::sandboxd_client::DEFAULT_SANDBOXD_SOCKET_PATH)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum LogFormat {
    #[default]
    Pretty,
    Json,
}

impl Default for HostAgentConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:9090".parse().unwrap(),
            auth_token: Zeroizing::new(String::new()),
            workspace_root: PathBuf::from("/var/lib/pico/workspaces"),
            sandboxd_socket_path: default_sandboxd_socket_path(),
            sandboxd_token: Zeroizing::new(String::new()),
            idle_timeout_secs: 300,
            default_runtime: RuntimeType::Firecracker,
            identity: HostIdentity::new(
                "unknown-host".into(),
                "default-cell".into(),
                "unknown-region".into(),
            ),
            drain_timeout_secs: 30,
            log_format: LogFormat::Pretty,
            draining: false,
            cpu_isolation_policy: CpuIsolationPolicy::None,
            cross_tenant_host: false,
            shared_host_metric_redaction: false,
        }
    }
}

impl HostAgentConfig {
    pub fn from_file_or_env() -> anyhow::Result<Self> {
        let config_path = std::env::var("PICO_HOST_AGENT_CONFIG")
            .unwrap_or_else(|_| "/etc/pico/host-agent.toml".into());

        let mut config = if let Ok(content) = std::fs::read_to_string(&config_path) {
            toml::from_str::<Self>(&content)
                .map_err(|err| anyhow::anyhow!("invalid config file {}: {err}", config_path))?
        } else {
            Self::default()
        };

        apply_env_overrides(&mut config);
        apply_identity_env_overrides(&mut config.identity);
        ensure_valid(&config)?;

        Ok(config)
    }
}

fn apply_env_overrides(config: &mut HostAgentConfig) {
    if let Ok(val) = std::env::var("PICO_HOST_AGENT_BIND_ADDR")
        && let Ok(addr) = SocketAddr::from_str(&val)
    {
        config.bind_addr = addr;
    }
    if let Ok(val) = std::env::var("PICO_HOST_AGENT_TOKEN")
        && !val.is_empty()
    {
        config.auth_token = Zeroizing::new(val);
    }
    if let Ok(val) = std::env::var("PICO_WORKSPACE_ROOT") {
        config.workspace_root = PathBuf::from(val);
    }
    if let Ok(val) = std::env::var("PICO_SANDBOXD_SOCKET") {
        config.sandboxd_socket_path = PathBuf::from(val);
    }
    if let Ok(val) = std::env::var("PICO_SANDBOXD_TOKEN")
        && !val.is_empty()
    {
        config.sandboxd_token = Zeroizing::new(val);
    }
    if let Ok(val) = std::env::var("PICO_IDLE_TIMEOUT_SECS")
        && let Ok(v) = val.parse::<u64>()
    {
        config.idle_timeout_secs = v;
    }
    if let Ok(val) = std::env::var("PICO_RUNTIME")
        && let Ok(rt) = RuntimeType::from_str(&val)
    {
        config.default_runtime = rt;
    }
    if let Ok(val) = std::env::var("PICO_DRAIN_TIMEOUT_SECS")
        && let Ok(v) = val.parse::<u64>()
    {
        config.drain_timeout_secs = v;
    }
    if let Ok(val) = std::env::var("PICO_LOG_FORMAT") {
        match val.as_str() {
            "json" => config.log_format = LogFormat::Json,
            _ => config.log_format = LogFormat::Pretty,
        }
    }
    if let Ok(val) = std::env::var("PICO_CPU_ISOLATION_POLICY") {
        match val.as_str() {
            "dedicated-cores-with-smt-exclusion" => {
                config.cpu_isolation_policy = CpuIsolationPolicy::DedicatedCoresWithSmtExclusion;
            }
            "dedicated-cores" => {
                config.cpu_isolation_policy = CpuIsolationPolicy::DedicatedCores;
            }
            _ => {
                config.cpu_isolation_policy = CpuIsolationPolicy::None;
            }
        }
    }
    if let Ok(val) = std::env::var("PICO_CROSS_TENANT_HOST") {
        config.cross_tenant_host = val.eq_ignore_ascii_case("true") || val == "1";
    }
    if let Ok(val) = std::env::var("PICO_SHARED_HOST_METRIC_REDACTION") {
        config.shared_host_metric_redaction = val.eq_ignore_ascii_case("true") || val == "1";
    }
}

fn apply_identity_env_overrides(identity: &mut HostIdentity) {
    if let Ok(val) = std::env::var("PICO_HOST_ID")
        && !val.is_empty()
    {
        identity.host_id = val;
    } else if identity.host_id.is_empty() {
        identity.host_id = HostIdentity::default_host_id();
    }

    if let Ok(val) = std::env::var("PICO_CELL_ID")
        && !val.is_empty()
    {
        identity.cell_id = val;
    } else if identity.cell_id.is_empty() {
        identity.cell_id = "default-cell".into();
    }

    if let Ok(val) = std::env::var("PICO_REGION")
        && !val.is_empty()
    {
        identity.region = val;
    } else if identity.region.is_empty() {
        identity.region = "unknown-region".into();
    }
}

fn ensure_valid(config: &HostAgentConfig) -> anyhow::Result<()> {
    if config.auth_token.is_empty() {
        anyhow::bail!("PICO_HOST_AGENT_TOKEN must be set")
    }
    if config.sandboxd_token.is_empty() {
        anyhow::bail!("PICO_SANDBOXD_TOKEN must be set")
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_valid_bind_addr() {
        let config = HostAgentConfig::default();
        assert_eq!(config.bind_addr.to_string(), "127.0.0.1:9090");
    }

    #[test]
    fn default_config_uses_firecracker() {
        let config = HostAgentConfig::default();
        assert_eq!(config.default_runtime, RuntimeType::Firecracker);
    }

    #[test]
    fn default_config_idle_timeout() {
        let config = HostAgentConfig::default();
        assert_eq!(config.idle_timeout_secs, 300);
    }

    #[test]
    fn env_override_bind_addr() {
        unsafe {
            std::env::set_var("PICO_HOST_AGENT_BIND_ADDR", "127.0.0.1:9999");
        }
        let mut config = HostAgentConfig::default();
        apply_env_overrides(&mut config);
        assert_eq!(config.bind_addr.to_string(), "127.0.0.1:9999");
        unsafe {
            std::env::remove_var("PICO_HOST_AGENT_BIND_ADDR");
        }
    }

    #[test]
    fn env_override_auth_token() {
        unsafe {
            std::env::set_var("PICO_HOST_AGENT_TOKEN", "super-secret");
        }
        let mut config = HostAgentConfig::default();
        apply_env_overrides(&mut config);
        assert_eq!(config.auth_token.as_str(), "super-secret");
        unsafe {
            std::env::remove_var("PICO_HOST_AGENT_TOKEN");
        }
    }

    #[test]
    fn env_override_runtime() {
        unsafe {
            std::env::set_var("PICO_RUNTIME", "qemu");
        }
        let mut config = HostAgentConfig::default();
        apply_env_overrides(&mut config);
        assert_eq!(config.default_runtime, RuntimeType::Qemu);
        unsafe {
            std::env::remove_var("PICO_RUNTIME");
        }
    }

    #[test]
    fn env_override_drain_timeout() {
        unsafe {
            std::env::set_var("PICO_DRAIN_TIMEOUT_SECS", "60");
        }
        let mut config = HostAgentConfig::default();
        apply_env_overrides(&mut config);
        assert_eq!(config.drain_timeout_secs, 60);
        unsafe {
            std::env::remove_var("PICO_DRAIN_TIMEOUT_SECS");
        }
    }

    #[test]
    fn env_override_log_format_json() {
        unsafe {
            std::env::set_var("PICO_LOG_FORMAT", "json");
        }
        let mut config = HostAgentConfig::default();
        apply_env_overrides(&mut config);
        assert_eq!(config.log_format, LogFormat::Json);
        unsafe {
            std::env::remove_var("PICO_LOG_FORMAT");
        }
    }

    #[test]
    fn log_format_serialization() {
        assert_eq!(
            serde_json::to_string(&LogFormat::Pretty).unwrap(),
            r#""pretty""#
        );
        assert_eq!(
            serde_json::to_string(&LogFormat::Json).unwrap(),
            r#""json""#
        );
    }

    #[test]
    fn configured_identity_is_preserved_without_env_override() {
        let mut identity =
            HostIdentity::new("cfg-host".into(), "cfg-cell".into(), "cfg-region".into());
        apply_identity_env_overrides(&mut identity);
        assert_eq!(identity.host_id, "cfg-host");
        assert_eq!(identity.cell_id, "cfg-cell");
        assert_eq!(identity.region, "cfg-region");
    }

    #[test]
    fn ensure_valid_requires_auth_token() {
        let config = HostAgentConfig::default();
        let err = ensure_valid(&config).unwrap_err();
        assert!(err.to_string().contains("PICO_HOST_AGENT_TOKEN"));
    }

    #[test]
    fn ensure_valid_requires_sandboxd_token() {
        let config = HostAgentConfig {
            auth_token: Zeroizing::new("host".into()),
            ..HostAgentConfig::default()
        };
        let err = ensure_valid(&config).unwrap_err();
        assert!(err.to_string().contains("PICO_SANDBOXD_TOKEN"));
    }
}

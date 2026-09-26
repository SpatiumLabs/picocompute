//! Runtime configuration for the PicoCompute API process.

use std::path::PathBuf;
use std::str::FromStr;

use pico_core::{DEFAULT_PERMIT_POLICY, RuntimeType};

/// Process configuration derived from environment variables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppConfig {
    pub bind_addr: String,
    pub token: String,
    pub workspace_root: PathBuf,
    pub idle_timeout_secs: u64,
    pub runtime: RuntimeBackend,
    pub run_env: RunEnv,
    pub public_host: Option<String>,
    pub tenant_id: String,
    pub principal_id: String,
    pub policy_text: String,
    pub lease_signing_key: Option<String>,
}

/// Sandbox runtime implementation selected for the API process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeBackend {
    Stub,
    Host(RuntimeType),
}

/// Logging and startup behavior mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunEnv {
    Development,
    Production,
}

impl RunEnv {
    pub fn from_env_value(value: &str) -> Self {
        match value {
            "production" => Self::Production,
            _ => Self::Development,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Development => "development",
            Self::Production => "production",
        }
    }
}

impl AppConfig {
    /// Loads API configuration from the process environment.
    pub fn from_env() -> anyhow::Result<Self> {
        let token = std::env::var("PICO_API_TOKEN")
            .map_err(|_| anyhow::anyhow!("PICO_API_TOKEN must be set"))?;
        Self::from_env_with_token(token)
    }

    fn from_env_with_token(token: String) -> anyhow::Result<Self> {
        let port = read_env("PICO_API_PORT")
            .map(|value| value.parse::<u16>())
            .transpose()
            .map_err(|err| anyhow::anyhow!("PICO_API_PORT must be a valid u16: {err}"))?
            .unwrap_or(8080);
        let host = read_env("PICO_API_HOST").unwrap_or_else(|| "0.0.0.0".into());
        let bind_addr = read_env("PICO_API_BIND_ADDR").unwrap_or_else(|| format!("{host}:{port}"));

        let workspace_root = read_env_os("PICO_WORKSPACE_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(default_workspace_root);

        let idle_timeout_secs = read_env("PICO_IDLE_TIMEOUT_SECS")
            .map(|value| value.parse::<u64>())
            .transpose()
            .map_err(|err| anyhow::anyhow!("PICO_IDLE_TIMEOUT_SECS must be a valid u64: {err}"))?
            .unwrap_or(300);

        let runtime = match read_env("PICO_RUNTIME")
            .unwrap_or_else(|| "firecracker".into())
            .as_str()
        {
            "stub" => RuntimeBackend::Stub,
            value => RuntimeBackend::Host(
                RuntimeType::from_str(value)
                    .map_err(|err| anyhow::anyhow!("invalid PICO_RUNTIME: {err}"))?,
            ),
        };

        let run_env = read_env("RUN_ENV")
            .map(|value| RunEnv::from_env_value(&value))
            .unwrap_or_else(|| {
                if cfg!(debug_assertions) {
                    RunEnv::Development
                } else {
                    RunEnv::Production
                }
            });

        let public_host = read_env("PICO_PUBLIC_HOST");
        let tenant_id = read_env("PICO_TENANT_ID").unwrap_or_else(|| "tnt_default".into());
        let principal_id = read_env("PICO_PRINCIPAL_ID").unwrap_or_else(|| "api".into());
        let policy_text = match read_env_os("PICO_POLICY_FILE") {
            Some(path) => std::fs::read_to_string(&path).map_err(|err| {
                anyhow::anyhow!(
                    "failed to read PICO_POLICY_FILE {}: {err}",
                    path.to_string_lossy()
                )
            })?,
            None => read_env("PICO_POLICY").unwrap_or_else(|| DEFAULT_PERMIT_POLICY.to_string()),
        };
        let lease_signing_key = read_env("PICO_LEASE_SIGNING_KEY");

        Ok(Self {
            bind_addr,
            token,
            workspace_root,
            idle_timeout_secs,
            runtime,
            run_env,
            public_host,
            tenant_id,
            principal_id,
            policy_text,
            lease_signing_key,
        })
    }
}

fn default_workspace_root() -> PathBuf {
    read_env_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join(".local/share/pico/workspaces")
}

fn read_env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|value| !value.is_empty())
}

fn read_env_os(key: &str) -> Option<std::ffi::OsString> {
    std::env::var_os(key).filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_env_defaults_unknown_values_to_development() {
        assert_eq!(RunEnv::from_env_value("development"), RunEnv::Development);
        assert_eq!(RunEnv::from_env_value("test"), RunEnv::Development);
        assert_eq!(RunEnv::from_env_value("production"), RunEnv::Production);
    }

    #[test]
    fn run_env_formats_as_stable_string() {
        assert_eq!(RunEnv::Development.as_str(), "development");
        assert_eq!(RunEnv::Production.as_str(), "production");
    }
}

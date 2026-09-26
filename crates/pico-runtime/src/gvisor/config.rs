//! gVisor adapter configuration with host-level defaults.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::RuntimeHardening;

/// gVisor adapter configuration resolved from host capabilities.
#[derive(Debug, Clone)]
pub struct GVisorConfig {
    /// Path to the `runsc` binary.
    pub runsc_binary_path: PathBuf,
    /// Root directory for runsc state (default: `/var/run/runsc`).
    pub runsc_root: PathBuf,
    /// Directory where OCI bundles are staged.
    pub bundle_dir: PathBuf,
    /// Path to the rootfs used for gVisor sandboxes.
    pub guest_rootfs_path: PathBuf,
    /// Total boot timeout including guest agent readiness.
    pub boot_timeout: Duration,
    /// When true, validate that paths exist during prepare.
    pub validate_paths: bool,
    /// Host-side runtime hardening configuration.
    pub hardening: RuntimeHardening,
}

impl Default for GVisorConfig {
    fn default() -> Self {
        Self::detect_defaults()
    }
}

impl GVisorConfig {
    /// Detects host defaults. Falls back to conventional paths when binaries
    /// or directories are not found.
    #[must_use]
    pub fn detect_defaults() -> Self {
        let runsc_binary_path = which("runsc").unwrap_or_else(|| PathBuf::from("/usr/bin/runsc"));
        let hardening = default_gvisor_hardening();

        Self {
            runsc_binary_path,
            runsc_root: PathBuf::from("/var/run/runsc"),
            bundle_dir: PathBuf::from("/var/lib/pico/gvisor"),
            guest_rootfs_path: PathBuf::from("/var/lib/pico/gvisor/rootfs"),
            boot_timeout: Duration::from_secs(30),
            validate_paths: true,
            hardening,
        }
    }

    /// Returns the OCI bundle directory for a sandbox.
    #[must_use]
    pub fn bundle_path(&self, sandbox_id: &str) -> PathBuf {
        self.bundle_dir.join(sandbox_id)
    }

    /// Returns the OCI config.json path for a sandbox.
    #[must_use]
    pub fn config_json_path(&self, sandbox_id: &str) -> PathBuf {
        self.bundle_path(sandbox_id).join("config.json")
    }

    /// Returns the runsc log directory for a sandbox.
    #[must_use]
    pub fn log_dir(&self, sandbox_id: &str) -> PathBuf {
        self.bundle_dir.join(sandbox_id).join("logs")
    }

    /// Validates that configured paths exist and required binaries are accessible.
    pub fn validate(&self) -> Result<(), String> {
        if self.validate_paths {
            if !self.runsc_binary_path.exists() {
                return Err(format!(
                    "runsc binary not found at {}",
                    self.runsc_binary_path.display()
                ));
            }
            if !self.guest_rootfs_path.exists() {
                return Err(format!(
                    "gVisor rootfs not found at {}",
                    self.guest_rootfs_path.display()
                ));
            }
        }
        Ok(())
    }
}

/// Searches PATH for a binary. Returns `None` when not found.
fn which(binary: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path_var| {
        std::env::split_paths(&path_var).find_map(|dir| {
            let candidate = dir.join(binary);
            candidate
                .exists()
                .then_some(candidate)
                .filter(|p| is_executable(p))
        })
    })
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|meta| meta.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

fn default_gvisor_hardening() -> RuntimeHardening {
    if std::env::var("PICO_GVISOR_HARDENING_ENABLED")
        .ok()
        .and_then(|v| match v.as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => None,
        })
        .unwrap_or(true)
    {
        RuntimeHardening::default()
    } else {
        RuntimeHardening {
            isolate_namespaces: false,
            unshare_mount_namespace: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_conventional_paths() {
        let config = GVisorConfig::default();
        assert_eq!(config.runsc_root, PathBuf::from("/var/run/runsc"));
        assert_eq!(config.bundle_dir, PathBuf::from("/var/lib/pico/gvisor"));
        assert!(!config.runsc_binary_path.as_os_str().is_empty());
    }

    #[test]
    fn bundle_path_encodes_sandbox_id() {
        let config = GVisorConfig::default();
        let path = config.bundle_path("sbx_test");
        assert!(path.ends_with("sbx_test"));
        assert!(path.starts_with("/var/lib/pico/gvisor"));
    }

    #[test]
    fn config_json_path_is_inside_bundle() {
        let config = GVisorConfig::default();
        let path = config.config_json_path("sbx_test");
        assert!(path.ends_with("config.json"));
        assert!(path.to_string_lossy().contains("sbx_test"));
    }

    #[test]
    fn log_dir_is_inside_bundle() {
        let config = GVisorConfig::default();
        let path = config.log_dir("sbx_test");
        assert!(path.ends_with("logs"));
        assert!(path.to_string_lossy().contains("sbx_test"));
    }

    #[test]
    fn with_validate_paths_disabled_config_always_passes() {
        let mut config = GVisorConfig::detect_defaults();
        config.validate_paths = false;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn gvisor_hardening_defaults_enable_isolation() {
        let hardening = RuntimeHardening::default();

        assert!(hardening.isolate_namespaces);
        assert!(hardening.unshare_mount_namespace);
        assert!(hardening.is_enabled());
    }

    #[test]
    fn gvisor_hardening_production_defaults_match_development() {
        let prod = RuntimeHardening::production_defaults();
        let dev = RuntimeHardening::default();

        assert_eq!(prod.isolate_namespaces, dev.isolate_namespaces);
        assert_eq!(prod.unshare_mount_namespace, dev.unshare_mount_namespace);
    }

    #[test]
    fn default_config_includes_hardening() {
        let config = GVisorConfig::detect_defaults();

        assert!(config.hardening.is_enabled());
        assert!(config.hardening.isolate_namespaces);
    }
}

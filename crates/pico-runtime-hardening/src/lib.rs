pub mod anomaly;
pub mod ebpf;
pub mod error;
pub mod fim;
pub mod guest_paths;
pub mod identity;
pub mod ioctl_policy;
pub mod namespaces;
pub mod output_quota;
pub mod proc_policy;
pub mod telemetry;

pub use anomaly::{
    AnomalyDetector, AnomalyEvent, AnomalySeverity, AnomalyType, DetectorConfig, TypePrior,
    sandbox_type_key,
};
pub use error::{HardeningError, HardeningResult};
pub use fim::{
    FileIntegrityChecker, FimAlert, FimHook, FimMode, FimOperation, FimProcessInfo, FimStats,
    IntegrityBaseline, open_flags_write_intent,
};
pub use guest_paths::{GuestHostOwnedBaseline, is_host_owned};
pub use identity::no_new_privs;
pub use ioctl_policy::{DeniedIoctlClass, denied_class, is_allowed as ioctl_is_allowed};
pub use namespaces::{NamespaceConfig, unshare_namespaces};
pub use output_quota::{OutputQuota, QuotaDecision};
pub use proc_policy::{ProcPolicyError, validate_proc_read};

pub fn init() {
    tracing::info!("pico-runtime-hardening library initialized");
}

pub fn apply_standard_isolation(unshare_mount: bool) -> HardeningResult<()> {
    // SAFETY: unshare(2) affects the calling process/thread. This is safe
    // in PicoCompute's single-sandbox-per-process model. Multi-sandbox adapters
    // should use clone(2) or a short-lived helper to avoid namespace leakage.
    //  tracks namespace isolation for multi-tenant processes.
    let ns_config = NamespaceConfig {
        mount: unshare_mount,
        pid: false,
        uts: true,
        ipc: true,
        net: false,
    };

    tracing::info!(
        mount = unshare_mount,
        uts = true,
        ipc = true,
        "applying standard runtime namespace isolation"
    );

    unshare_namespaces(&ns_config)?;
    no_new_privs()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn apply_standard_isolation_with_unshare_mount() {
        let result = apply_standard_isolation(true);
        assert!(result.is_ok());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn apply_standard_isolation_without_unshare_mount() {
        let result = apply_standard_isolation(false);
        assert!(result.is_ok());
    }

    #[test]
    fn hardening_error_type_conversion() {
        let err = HardeningError::PlatformNotSupported;
        let result: HardeningResult<()> = Err(err);
        assert!(result.is_err());
    }

    #[test]
    fn hardening_error_display() {
        let err = HardeningError::NamespaceIsolation("ns error".into());
        assert!(err.to_string().contains("namespace isolation failed"));
    }
}

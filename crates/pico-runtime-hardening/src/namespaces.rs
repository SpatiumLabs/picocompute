#[cfg(target_os = "linux")]
mod linux_impl {
    use rustix::thread::UnshareFlags;
    use tracing::info;

    use crate::error::{HardeningError, HardeningResult};

    pub struct NamespaceConfig {
        pub mount: bool,
        pub pid: bool,
        pub uts: bool,
        pub ipc: bool,
        pub net: bool,
    }

    impl Default for NamespaceConfig {
        fn default() -> Self {
            Self {
                mount: true,
                pid: false,
                uts: true,
                ipc: true,
                net: false,
            }
        }
    }

    impl NamespaceConfig {
        pub fn all() -> Self {
            Self {
                mount: true,
                pid: true,
                uts: true,
                ipc: true,
                net: true,
            }
        }

        pub fn flags(&self) -> UnshareFlags {
            let mut flags = UnshareFlags::empty();
            if self.mount {
                flags |= UnshareFlags::NEWNS;
            }
            if self.pid {
                flags |= UnshareFlags::NEWPID;
            }
            if self.uts {
                flags |= UnshareFlags::NEWUTS;
            }
            if self.ipc {
                flags |= UnshareFlags::NEWIPC;
            }
            if self.net {
                flags |= UnshareFlags::NEWNET;
            }
            flags
        }
    }

    pub fn unshare_namespaces(config: &NamespaceConfig) -> HardeningResult<()> {
        let flags = config.flags();
        if flags.is_empty() {
            return Ok(());
        }

        info!(
            mount = config.mount,
            pid = config.pid,
            uts = config.uts,
            ipc = config.ipc,
            net = config.net,
            "unsharing namespaces"
        );

        // SAFETY: unshare_unsafe is unsafe because it can introduce undefined
        // behavior if memory allocations exist in threads that should not be
        // duplicated. We call it early in process initialization before any
        // significant allocations have occurred.
        unsafe { rustix::thread::unshare_unsafe(flags) }
            .map_err(|err| HardeningError::NamespaceIsolation(format!("unshare failed: {err}")))?;

        crate::telemetry::emit_namespace_isolation(config);

        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
mod linux_impl {
    use tracing::info;

    use crate::error::HardeningResult;

    pub struct NamespaceConfig {
        pub mount: bool,
        pub pid: bool,
        pub uts: bool,
        pub ipc: bool,
        pub net: bool,
    }

    impl Default for NamespaceConfig {
        fn default() -> Self {
            Self {
                mount: true,
                pid: false,
                uts: true,
                ipc: true,
                net: false,
            }
        }
    }

    impl NamespaceConfig {
        pub fn all() -> Self {
            Self {
                mount: true,
                pid: true,
                uts: true,
                ipc: true,
                net: true,
            }
        }

        pub fn flags(&self) -> u32 {
            0
        }
    }

    pub fn unshare_namespaces(_config: &NamespaceConfig) -> HardeningResult<()> {
        info!("pico-runtime-hardening: namespace isolation skipped (non-Linux)");
        Ok(())
    }
}

pub use linux_impl::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_correct_values() {
        let config = NamespaceConfig::default();
        assert!(config.mount, "mount should be true");
        assert!(!config.pid, "pid should be false");
        assert!(config.uts, "uts should be true");
        assert!(config.ipc, "ipc should be true");
        assert!(!config.net, "net should be false");
    }

    #[test]
    fn all_config_enables_all_namespaces() {
        let config = NamespaceConfig::all();
        assert!(config.mount);
        assert!(config.pid);
        assert!(config.uts);
        assert!(config.ipc);
        assert!(config.net);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn flags_empty_on_non_linux() {
        let config = NamespaceConfig::default();
        assert_eq!(config.flags(), 0);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn unshare_namespaces_ok_on_non_linux() {
        let config = NamespaceConfig::default();
        assert!(unshare_namespaces(&config).is_ok());
    }
}

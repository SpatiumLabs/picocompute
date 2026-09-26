#[cfg(target_os = "linux")]
mod linux_impl {
    use tracing::{info, warn};

    use rustix::thread::{CapabilitySet as CapBits, SecureComputingMode};

    use crate::ProfileError;
    use crate::ProfileResult;
    use crate::telemetry;

    #[derive(Debug, Clone)]
    pub struct CapabilitySet {
        pub name: String,
        caps: CapBits,
    }

    impl CapabilitySet {
        pub fn new(name: impl Into<String>) -> Self {
            Self {
                name: name.into(),
                caps: CapBits::empty(),
            }
        }

        pub fn with_cap(mut self, cap: CapBits) -> Self {
            self.caps |= cap;
            self
        }

        pub fn caps(&self) -> CapBits {
            self.caps
        }

        pub fn is_empty(&self) -> bool {
            self.caps.is_empty()
        }

        pub fn host_agent() -> Self {
            Self::new("host-agent")
                .with_cap(CapBits::NET_BIND_SERVICE)
                .with_cap(CapBits::SYS_ADMIN)
                .with_cap(CapBits::SYS_RESOURCE)
                .with_cap(CapBits::SYS_PTRACE)
                .with_cap(CapBits::DAC_OVERRIDE)
        }

        pub fn sandboxd() -> Self {
            Self::new("sandboxd")
                .with_cap(CapBits::KILL)
                .with_cap(CapBits::SYS_PTRACE)
                .with_cap(CapBits::SYS_ADMIN)
                .with_cap(CapBits::SYS_RESOURCE)
                .with_cap(CapBits::DAC_OVERRIDE)
        }

        pub fn guest_agent() -> Self {
            Self::new("guest-agent")
                .with_cap(CapBits::KILL)
                .with_cap(CapBits::SYS_RESOURCE)
                .with_cap(CapBits::SYS_PTRACE)
        }

        pub fn runtime_backend() -> Self {
            Self::new("runtime-backend")
                .with_cap(CapBits::SYS_ADMIN)
                .with_cap(CapBits::SYS_RESOURCE)
                .with_cap(CapBits::SYS_PTRACE)
                .with_cap(CapBits::NET_ADMIN)
                .with_cap(CapBits::NET_RAW)
                .with_cap(CapBits::DAC_OVERRIDE)
                .with_cap(CapBits::MKNOD)
        }

        pub fn network_agent() -> Self {
            Self::new("network-agent")
                .with_cap(CapBits::NET_ADMIN)
                .with_cap(CapBits::NET_RAW)
                .with_cap(CapBits::SYS_ADMIN)
                .with_cap(CapBits::SYS_RESOURCE)
        }

        pub fn helper() -> Self {
            Self::new("helper")
                .with_cap(CapBits::SYS_ADMIN)
                .with_cap(CapBits::SYS_RESOURCE)
                .with_cap(CapBits::NET_ADMIN)
                .with_cap(CapBits::MKNOD)
                .with_cap(CapBits::DAC_OVERRIDE)
        }

        pub fn bounding() -> Self {
            Self {
                name: "bounding".to_string(),
                caps: CapBits::all(),
            }
        }
    }

    pub fn drop_all_capabilities() -> ProfileResult<()> {
        info!("dropping all Linux capabilities");

        let bounding = CapabilitySet::bounding();
        for cap in bounding.caps().iter() {
            drop_single_capability(cap)?;
        }

        telemetry::capabilities_dropped("current").emit();

        Ok(())
    }

    pub fn drop_capabilities(caps_to_drop: &CapabilitySet) -> ProfileResult<()> {
        info!(
            name = %caps_to_drop.name,
            count = caps_to_drop.caps.iter().count(),
            "dropping Linux capabilities from bounding set"
        );

        for cap in caps_to_drop.caps.iter() {
            drop_single_capability(cap)?;
        }

        telemetry::capabilities_dropped(caps_to_drop.name.clone()).emit();

        Ok(())
    }

    pub fn keep_capabilities(caps_to_keep: &CapabilitySet) -> ProfileResult<()> {
        info!(
            name = %caps_to_keep.name,
            keep_count = caps_to_keep.caps.iter().count(),
            "minimizing Linux capabilities set"
        );

        let bounding = CapabilitySet::bounding();
        let keep_set = caps_to_keep.caps;

        for cap in bounding.caps().iter() {
            if !keep_set.contains(cap)
                && let Err(e) = drop_single_capability(cap)
            {
                warn!(
                    cap = ?cap,
                    error = %e,
                    "failed to drop capability, continuing"
                );
            }
        }

        telemetry::capabilities_dropped(caps_to_keep.name.clone()).emit();

        Ok(())
    }

    fn drop_single_capability(cap: CapBits) -> ProfileResult<()> {
        rustix::thread::configure_capability_in_ambient_set(cap, false).map_err(|e| {
            ProfileError::CapabilityError(format!(
                "failed to drop ambient capability {:?}: {}",
                cap, e
            ))
        })?;

        rustix::thread::remove_capability_from_bounding_set(cap).map_err(|e| {
            ProfileError::CapabilityError(format!(
                "failed to drop bounding capability {:?}: {}",
                cap, e
            ))
        })?;

        Ok(())
    }

    pub fn set_no_new_privs() -> ProfileResult<()> {
        info!("setting PR_SET_NO_NEW_PRIVS");
        rustix::thread::set_no_new_privs(true)
            .map_err(|e| ProfileError::NoNewPrivsFailed(std::io::Error::from(e)))
    }

    pub fn set_seccomp_filter_mode() -> ProfileResult<()> {
        info!("setting PR_SET_SECCOMP to SECCOMP_MODE_FILTER");
        rustix::thread::set_secure_computing_mode(SecureComputingMode::Filter)
            .map_err(|e| ProfileError::SeccompModeFailed(std::io::Error::from(e)))
    }
}

#[cfg(not(target_os = "linux"))]
mod linux_impl {
    use tracing::info;

    use crate::ProfileResult;
    use crate::telemetry;

    #[derive(Debug, Clone)]
    pub struct CapabilitySet {
        pub name: String,
    }

    impl CapabilitySet {
        pub fn new(name: impl Into<String>) -> Self {
            Self { name: name.into() }
        }

        pub fn is_empty(&self) -> bool {
            true
        }

        pub fn host_agent() -> Self {
            Self::new("host-agent")
        }

        pub fn sandboxd() -> Self {
            Self::new("sandboxd")
        }

        pub fn guest_agent() -> Self {
            Self::new("guest-agent")
        }

        pub fn runtime_backend() -> Self {
            Self::new("runtime-backend")
        }

        pub fn network_agent() -> Self {
            Self::new("network-agent")
        }

        pub fn helper() -> Self {
            Self::new("helper")
        }

        pub fn bounding() -> Self {
            Self::new("bounding")
        }
    }

    pub fn drop_all_capabilities() -> ProfileResult<()> {
        info!("pico-seccomp: capability dropping skipped (non-Linux)");
        telemetry::capabilities_dropped("current").emit();
        Ok(())
    }

    pub fn drop_capabilities(_caps_to_drop: &CapabilitySet) -> ProfileResult<()> {
        info!("pico-seccomp: capability dropping skipped (non-Linux)");
        telemetry::capabilities_dropped(_caps_to_drop.name.clone()).emit();
        Ok(())
    }

    pub fn keep_capabilities(_caps_to_keep: &CapabilitySet) -> ProfileResult<()> {
        info!("pico-seccomp: capability minimization skipped (non-Linux)");
        telemetry::capabilities_dropped(_caps_to_keep.name.clone()).emit();
        Ok(())
    }

    pub fn set_no_new_privs() -> ProfileResult<()> {
        info!("pico-seccomp: no_new_privs skipped (non-Linux)");
        Ok(())
    }

    pub fn set_seccomp_filter_mode() -> ProfileResult<()> {
        info!("pico-seccomp: seccomp filter mode skipped (non-Linux)");
        Ok(())
    }
}

pub use linux_impl::*;

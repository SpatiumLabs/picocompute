#[cfg(target_os = "linux")]
mod linux_impl {
    use tracing::info;

    use crate::error::{HardeningError, HardeningResult};

    pub fn no_new_privs() -> HardeningResult<()> {
        info!("setting PR_SET_NO_NEW_PRIVS via pico-runtime-hardening");
        rustix::thread::set_no_new_privs(true)
            .map_err(|err| HardeningError::NoNewPrivsFailed(format!("{err}")))?;
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
mod linux_impl {
    use tracing::info;

    use crate::error::HardeningResult;

    pub fn no_new_privs() -> HardeningResult<()> {
        info!("pico-runtime-hardening: no_new_privs skipped (non-Linux)");
        Ok(())
    }
}

pub use linux_impl::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_new_privs_returns_ok() {
        assert!(no_new_privs().is_ok());
    }
}

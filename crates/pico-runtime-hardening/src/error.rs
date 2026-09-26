use thiserror::Error;

#[derive(Error, Debug)]
pub enum HardeningError {
    #[error("namespace isolation failed: {0}")]
    NamespaceIsolation(String),

    #[error("no_new_privs prctl failed: {0}")]
    NoNewPrivsFailed(String),

    #[error("hardening not supported on this platform")]
    PlatformNotSupported,
}

pub type HardeningResult<T> = Result<T, HardeningError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_namespace_isolation() {
        let err = HardeningError::NamespaceIsolation("test error".into());
        assert_eq!(err.to_string(), "namespace isolation failed: test error");
    }

    #[test]
    fn display_no_new_privs_failed() {
        let err = HardeningError::NoNewPrivsFailed("prctl error".into());
        assert_eq!(err.to_string(), "no_new_privs prctl failed: prctl error");
    }

    #[test]
    fn display_platform_not_supported() {
        let err = HardeningError::PlatformNotSupported;
        assert_eq!(err.to_string(), "hardening not supported on this platform");
    }

    #[test]
    fn hardening_result_type_works() {
        let ok: HardeningResult<()> = Ok(());
        assert!(ok.is_ok());

        let err: HardeningResult<()> = Err(HardeningError::PlatformNotSupported);
        assert!(err.is_err());
    }
}

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProfileError {
    #[error("failed to read profile file at {path}: {source}")]
    FileRead {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse profile JSON: {0}")]
    JsonParse(#[from] serde_json::Error),

    #[error("failed to compile seccomp filter: {0}")]
    Compilation(String),

    #[error("failed to apply seccomp filter: {0}")]
    FilterApplication(String),

    #[error("profile not found for component '{component}'")]
    ProfileNotFound { component: String },

    #[error("capability operation failed: {0}")]
    CapabilityError(String),

    #[error("architecture not supported: {arch}")]
    UnsupportedArch { arch: String },

    #[error("no_new_privs prctl failed: {0}")]
    NoNewPrivsFailed(std::io::Error),

    #[error("seccomp filter mode prctl failed: {0}")]
    SeccompModeFailed(std::io::Error),

    #[error("seccomp not available on this platform")]
    PlatformNotSupported,
}

pub type ProfileResult<T> = Result<T, ProfileError>;

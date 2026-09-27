use thiserror::Error;

#[derive(Debug, Error)]
pub enum ImageError {
    #[error("digest mismatch for {artifact}: expected {expected}, got {actual}")]
    DigestMismatch {
        artifact: String,
        expected: String,
        actual: String,
    },

    #[error("package not found in lock file: {name}")]
    PackageNotFound { name: String },

    #[error("filesystem check failed: {0}")]
    FsckFailed(String),

    #[error("manifest validation failed: {0}")]
    ManifestValidationFailed(String),

    #[error("guest agent build failed: {0}")]
    GuestAgentBuildFailed(String),

    #[error("guest-agent version is missing from image definition")]
    GuestAgentVersionMissing,

    #[error("guest-agent version incompatible: declared {declared} but found {found}")]
    GuestAgentVersionIncompatible { declared: String, found: String },

    #[error("missing required tool: {tool}")]
    MissingTool { tool: String },

    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("parse error: {0}")]
    ParseError(String),

    #[error("mount layout error: {0}")]
    MountLayoutError(String),

    #[error("reserved path not empty: {path}")]
    ReservedPathNotEmpty { path: String },

    #[error(
        "kernel config validation failed for profile {profile}: missing options {missing_options:?}"
    )]
    KernelConfigValidationFailed {
        profile: String,
        missing_options: Vec<String>,
    },

    #[error("signing key not available: {0}")]
    SigningKeyUnavailable(String),

    #[error("signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    #[error("unsigned image rejected in production mode: {image_id}")]
    UnsignedImageRejected { image_id: String },

    #[error("missing host artifact '{artifact}' for image {image_id}: {reason}")]
    MissingHostArtifact {
        artifact: String,
        image_id: String,
        reason: String,
    },

    #[error("size mismatch for {artifact}: expected {expected}, got {actual}")]
    SizeMismatch {
        artifact: String,
        expected: u64,
        actual: u64,
    },

    #[error("SBOM generation failed: {0}")]
    SbomGenerationFailed(String),

    #[error("SBOM validation failed: {0}")]
    SbomValidationFailed(String),

    #[error("provenance generation failed: {0}")]
    ProvenanceGenerationFailed(String),

    #[error("provenance validation failed: {0}")]
    ProvenanceValidationFailed(String),

    #[error("key format error: {0}")]
    KeyFormatError(String),

    #[error("composition validation failed: {0}")]
    CompositionValidationFailed(String),

    #[error("too many environment layers: {count} exceeds max {max}; collapse toolkits first")]
    TooManyLayers { count: usize, max: usize },

    #[error("incompatible environment composition: {reason}")]
    IncompatibleComposition { reason: String },
}

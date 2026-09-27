use pico_core::mount::PathLifecycle;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageDefinition {
    pub image: ImageInfo,
    pub base: BaseSource,
    #[serde(default)]
    pub packages: std::collections::BTreeMap<String, String>,
    pub guest_agent: GuestAgentSource,
    pub filesystem: FilesystemConfig,
    #[serde(default)]
    pub mounts: Vec<MountDef>,
    #[serde(default)]
    pub kernel: Option<KernelSource>,
    /// Optional composable environment declaration (base/workspace/toolkit
    /// layers). Absent means the monolithic single-rootfs build.
    #[serde(default)]
    pub environment: Option<EnvironmentDef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageInfo {
    pub id: String,
    pub version: String,
    pub source_date_epoch: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseSource {
    pub source: SourceRef,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceRef {
    pub url: String,
    pub digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "source")]
pub enum GuestAgentSource {
    #[serde(rename = "workspace")]
    Workspace {
        #[serde(default)]
        version: Option<String>,
        #[serde(default)]
        protocol_version: Option<String>,
        #[serde(default)]
        capabilities: Vec<String>,
    },
    #[serde(rename = "prebuilt")]
    Prebuilt {
        path: String,
        digest: String,
        #[serde(default)]
        version: Option<String>,
        #[serde(default)]
        protocol_version: Option<String>,
        #[serde(default)]
        capabilities: Vec<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemConfig {
    pub size: String,
    pub label: String,
    pub uuid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountDef {
    pub path: String,
    pub class: String,
    pub writable: bool,
    pub lifecycle: PathLifecycle,
}

/// Composable environment declaration: the layers to stack, in order.
///
/// Layers are declared in overlay precedence order. Exactly one `base` and one
/// `workspace` entry are required; `toolkit` entries are optional and the
/// first toolkit is the topmost layer, so shadowing order is explicit rather
/// than inferred from names.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentDef {
    /// Declared layers in overlay precedence order.
    pub layers: Vec<EnvironmentLayerDef>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentLayerRole {
    /// Immutable OS root, bottom of the stack. Exactly one required.
    Base,
    /// Immutable workspace seed. Exactly one required.
    Workspace,
    /// Immutable toolkit extension, topmost first. Zero or more.
    Toolkit,
}

impl EnvironmentLayerRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Base => "base",
            Self::Workspace => "workspace",
            Self::Toolkit => "toolkit",
        }
    }

    /// Map a declared role onto the composition layer kind.
    pub fn layer_kind(self) -> crate::layers::EnvironmentLayerKind {
        match self {
            Self::Base => crate::layers::EnvironmentLayerKind::Base,
            Self::Workspace => crate::layers::EnvironmentLayerKind::Workspace,
            Self::Toolkit => crate::layers::EnvironmentLayerKind::Toolkit,
        }
    }
}

/// One declared environment layer, resolved from a local materialized file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentLayerDef {
    /// Position class in the overlay stack.
    pub role: EnvironmentLayerRole,
    /// Stable layer name; single safe path component on the host.
    pub name: String,
    /// Path to the already-materialized layer image (EROFS/ext4/squashfs).
    pub path: String,
    /// Media type recorded in the composition.
    #[serde(default = "default_layer_media_type")]
    pub media_type: String,
    /// Human release version label.
    #[serde(default)]
    pub version: Option<String>,
    /// Per-layer SBOM digest. Required for promotion.
    #[serde(default)]
    pub sbom_digest: Option<String>,
    /// Per-layer provenance digest. Required for promotion.
    #[serde(default)]
    pub provenance_digest: Option<String>,
    /// Per-layer detached signature digest. Required for promotion.
    #[serde(default)]
    pub signature_digest: Option<String>,
}

fn default_layer_media_type() -> String {
    "application/vnd.pico.layer.erofs".into()
}

impl EnvironmentLayerDef {
    /// Resolve the declared layer against its materialized file.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::ImageError`] when the path is not valid UTF-8,
    /// the file cannot be read, or the resolved descriptor fails
    /// [`crate::layers::validate_environment_layer`].
    pub fn resolve(&self) -> Result<crate::layers::EnvironmentLayer, crate::error::ImageError> {
        use crate::error::ImageError;

        let path = camino::Utf8Path::new(&self.path);
        let digest = crate::render::compute_file_digest(path)?;
        let size = std::fs::metadata(path)
            .map_err(|e| {
                ImageError::ParseError(format!("failed to stat layer {}: {e}", self.path))
            })?
            .len();
        let mut layer = crate::layers::EnvironmentLayer::new(
            self.name.clone(),
            self.role.layer_kind(),
            digest,
            size,
            self.media_type.clone(),
        )?;
        layer.version = self.version.clone();
        layer.sbom_digest = self.sbom_digest.clone();
        layer.provenance_digest = self.provenance_digest.clone();
        layer.signature_digest = self.signature_digest.clone();
        Ok(layer)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelSource {
    pub backend: String,
    pub variant: String,
    pub version: String,
    #[serde(default)]
    pub cmdline: Option<String>,
    #[serde(default)]
    pub vmlinux_path: Option<String>,
    #[serde(default)]
    pub initrd_path: Option<String>,
    #[serde(default)]
    pub firmware_path: Option<String>,
    #[serde(default)]
    pub config_profile: Option<String>,
}

impl KernelSource {
    pub fn profile_id(&self) -> String {
        self.config_profile
            .clone()
            .unwrap_or_else(|| format!("{}-{}-v1", self.backend, std::env::consts::ARCH))
    }
}

impl ImageDefinition {
    pub fn load(path: &camino::Utf8Path) -> Result<Self, crate::error::ImageError> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            crate::error::ImageError::ParseError(format!("failed to read {}: {}", path, e))
        })?;
        toml::from_str(&content)
            .map_err(|e| crate::error::ImageError::ParseError(format!("invalid definition: {}", e)))
    }
}

impl GuestAgentSource {
    pub fn version(&self) -> Option<&str> {
        match self {
            GuestAgentSource::Workspace { version, .. } => version.as_deref(),
            GuestAgentSource::Prebuilt { version, .. } => version.as_deref(),
        }
    }

    pub fn protocol_version(&self) -> Option<&str> {
        match self {
            GuestAgentSource::Workspace {
                protocol_version, ..
            } => protocol_version.as_deref(),
            GuestAgentSource::Prebuilt {
                protocol_version, ..
            } => protocol_version.as_deref(),
        }
    }

    pub fn capabilities(&self) -> &[String] {
        match self {
            GuestAgentSource::Workspace { capabilities, .. } => capabilities,
            GuestAgentSource::Prebuilt { capabilities, .. } => capabilities,
        }
    }
}

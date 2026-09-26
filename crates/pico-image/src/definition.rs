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

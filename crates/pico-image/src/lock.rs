use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageLock {
    pub metadata: LockMetadata,
    pub base: LockBase,
    pub guest_agent: LockArtifact,
    #[serde(default)]
    pub packages: Vec<LockedPackage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockMetadata {
    pub image_id: String,
    pub version: String,
    pub source_date_epoch: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockBase {
    pub url: String,
    pub digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockArtifact {
    pub digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockedPackage {
    pub name: String,
    pub version: String,
    pub digest: String,
}

impl PackageLock {
    pub fn load(path: &camino::Utf8Path) -> Result<Self, crate::error::ImageError> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            crate::error::ImageError::ParseError(format!("failed to read {}: {}", path, e))
        })?;
        toml::from_str(&content)
            .map_err(|e| crate::error::ImageError::ParseError(format!("invalid lock file: {}", e)))
    }

    pub fn save(&self, path: &camino::Utf8Path) -> Result<(), crate::error::ImageError> {
        let content = toml::to_string_pretty(self).map_err(|e| {
            crate::error::ImageError::ParseError(format!("failed to serialize lock: {}", e))
        })?;
        std::fs::write(path, content)?;
        Ok(())
    }
}

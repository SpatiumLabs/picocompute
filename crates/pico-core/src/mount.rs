use serde::{Deserialize, Serialize};

pub const CANONICAL_WORKSPACE: &str = "/workspace";
pub const CANONICAL_RUNTIME_TMP: &str = "/run/pico/tmp";
pub const CANONICAL_SECRETS_TMPFS: &str = "/run/pico/secrets";
pub const CANONICAL_GUEST_LOGS: &str = "/var/log/pico";

pub const GUEST_MOUNT_DISCOVERY_PATH: &str = "/etc/pico/mount-contract.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MountClass {
    Workspace,
    RuntimeTmp,
    Secret,
    GuestLogs,
}

impl MountClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            MountClass::Workspace => "workspace",
            MountClass::RuntimeTmp => "runtime_tmp",
            MountClass::Secret => "secret",
            MountClass::GuestLogs => "guest_logs",
        }
    }

    pub fn default_lifecycle(&self) -> PathLifecycle {
        match self {
            MountClass::Workspace | MountClass::GuestLogs => PathLifecycle::Persistent,
            MountClass::RuntimeTmp | MountClass::Secret => PathLifecycle::Ephemeral,
        }
    }

    pub fn default_writable(&self) -> bool {
        match self {
            MountClass::Secret => false,
            MountClass::Workspace | MountClass::RuntimeTmp | MountClass::GuestLogs => true,
        }
    }

    pub fn canonical_path(&self) -> &'static str {
        match self {
            MountClass::Workspace => CANONICAL_WORKSPACE,
            MountClass::RuntimeTmp => CANONICAL_RUNTIME_TMP,
            MountClass::Secret => CANONICAL_SECRETS_TMPFS,
            MountClass::GuestLogs => CANONICAL_GUEST_LOGS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathLifecycle {
    Persistent,
    Ephemeral,
    CopyOnWrite,
}

impl PathLifecycle {
    pub fn excluded_from_snapshot(&self) -> bool {
        matches!(self, PathLifecycle::Ephemeral)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountEntry {
    pub path: String,
    pub class: MountClass,
    pub writable: bool,
    pub lifecycle: PathLifecycle,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountContract {
    pub version: String,
    pub mounts: Vec<MountEntry>,
}

impl MountContract {
    pub fn snapshot_excluded_classes(&self) -> Vec<String> {
        self.mounts
            .iter()
            .filter(|m| m.lifecycle.excluded_from_snapshot())
            .map(|m| m.class.as_str().to_string())
            .collect()
    }

    pub fn is_valid(&self) -> Result<(), String> {
        for entry in &self.mounts {
            if entry.class == MountClass::Secret && entry.lifecycle != PathLifecycle::Ephemeral {
                return Err(format!(
                    "secret mount '{}' must have ephemeral lifecycle",
                    entry.path
                ));
            }
            if entry.class == MountClass::Secret && entry.writable {
                return Err(format!(
                    "secret mount '{}' must not be writable",
                    entry.path
                ));
            }
            if entry.class.default_lifecycle() != entry.lifecycle {
                return Err(format!(
                    "mount class '{}' at '{}' has lifecycle {:?} but default is {:?}",
                    entry.class.as_str(),
                    entry.path,
                    entry.lifecycle,
                    entry.class.default_lifecycle()
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotInfo {
    pub filesystem: bool,
    pub memory: bool,
    pub excluded_mount_classes: Vec<String>,
}

//! Snapshot resource shape records.
//!
//! CPU, memory, and device model information stored in snapshot metadata
//! for compatibility validation without loading snapshot blobs.

use serde::{Deserialize, Serialize};

/// CPU architecture and feature requirements for a snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CpuShape {
    /// CPU architecture (e.g., "x86_64", "aarch64").
    pub architecture: String,
    /// CPU vendor (e.g., "Intel", "AMD", "ARM").
    #[serde(default)]
    pub vendor: Option<String>,
    /// CPU template applied at snapshot time (e.g., "T2", "T3", "C3").
    #[serde(default)]
    pub template: Option<String>,
    /// Required CPU features (e.g., ["sse4_2", "avx2", "aes"]).
    #[serde(default)]
    pub required_features: Vec<String>,
}

impl CpuShape {
    /// Creates a new CPU shape with a required architecture.
    pub fn new(architecture: impl Into<String>) -> Self {
        Self {
            architecture: architecture.into(),
            vendor: None,
            template: None,
            required_features: Vec::new(),
        }
    }

    /// True if this CPU shape is compatible with another host shape.
    ///
    /// Architecture and vendor must match exactly. The host must support
    /// all features required by the snapshot.
    pub fn is_compatible_with(&self, host: &CpuShape) -> bool {
        if self.architecture != host.architecture {
            return false;
        }
        if let (Some(snap_vendor), Some(host_vendor)) = (&self.vendor, &host.vendor)
            && snap_vendor != host_vendor
        {
            return false;
        }
        for feature in &self.required_features {
            if !host.required_features.iter().any(|f| f == feature) {
                return false;
            }
        }
        true
    }
}

/// Memory shape for a snapshot.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemoryShape {
    /// Memory in megabytes.
    pub memory_mb: u64,
    /// Virtual CPU count.
    pub vcpus: u32,
}

impl MemoryShape {
    /// True if a host with `host` shape can accommodate this snapshot.
    ///
    /// The host must have at least as much memory and at least as many vCPUs.
    pub fn fits_on_host(&self, host: &MemoryShape) -> bool {
        self.memory_mb <= host.memory_mb && self.vcpus <= host.vcpus
    }
}

/// Device model information for a snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceModel {
    /// Machine type (e.g., "pc", "q35", "virt").
    pub machine_type: String,
    /// Device configuration version or profile.
    #[serde(default)]
    pub config_version: Option<String>,
    /// Required device features (e.g., ["virtio-net", "virtio-blk"]).
    #[serde(default)]
    pub required_devices: Vec<String>,
}

impl DeviceModel {
    /// Creates a new device model with a machine type.
    pub fn new(machine_type: impl Into<String>) -> Self {
        Self {
            machine_type: machine_type.into(),
            config_version: None,
            required_devices: Vec::new(),
        }
    }

    /// True if this device model is compatible with a host device model.
    pub fn is_compatible_with(&self, host: &DeviceModel) -> bool {
        if self.machine_type != host.machine_type {
            return false;
        }
        for device in &self.required_devices {
            if !host.required_devices.iter().any(|d| d == device) {
                return false;
            }
        }
        true
    }
}

/// Backend information stored in snapshot metadata for compatibility.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackendRecord {
    /// Backend family (e.g., "firecracker", "qemu", "gvisor").
    pub backend_type: String,
    /// Exact backend version at snapshot time.
    pub backend_version: String,
    /// Protocol version spoken by the guest agent.
    pub protocol_version: String,
    /// Guest agent version.
    #[serde(default)]
    pub guest_agent_version: Option<String>,
}

impl BackendRecord {
    /// True if the snapshot backend matches the host backend family.
    pub fn is_same_family(&self, host_backend: &str) -> bool {
        self.backend_type == host_backend
    }

    /// True if the host version is compatible with the snapshot version.
    ///
    /// This is a simplified check; production may compare version ranges.
    pub fn is_version_compatible(&self, host_version: &str) -> bool {
        self.backend_version == host_version
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_shape_compatible_same() {
        let snap = CpuShape {
            architecture: "x86_64".into(),
            vendor: Some("Intel".into()),
            template: Some("T2".into()),
            required_features: vec!["sse4_2".into(), "aes".into()],
        };
        let host = snap.clone();
        assert!(snap.is_compatible_with(&host));
    }

    #[test]
    fn cpu_shape_incompatible_architecture() {
        let snap = CpuShape::new("x86_64");
        let host = CpuShape::new("aarch64");
        assert!(!snap.is_compatible_with(&host));
    }

    #[test]
    fn cpu_shape_incompatible_missing_feature() {
        let snap = CpuShape {
            architecture: "x86_64".into(),
            vendor: None,
            template: None,
            required_features: vec!["avx2".into()],
        };
        let host = CpuShape {
            architecture: "x86_64".into(),
            vendor: None,
            template: None,
            required_features: vec!["sse4_2".into()],
        };
        assert!(!snap.is_compatible_with(&host));
    }

    #[test]
    fn cpu_shape_compatible_extra_host_features() {
        let snap = CpuShape {
            architecture: "x86_64".into(),
            vendor: None,
            template: None,
            required_features: vec!["sse4_2".into()],
        };
        let host = CpuShape {
            architecture: "x86_64".into(),
            vendor: None,
            template: None,
            required_features: vec!["sse4_2".into(), "avx2".into(), "aes".into()],
        };
        assert!(snap.is_compatible_with(&host));
    }

    #[test]
    fn memory_shape_fits_on_host() {
        let snap = MemoryShape {
            memory_mb: 1024,
            vcpus: 2,
        };
        let host = MemoryShape {
            memory_mb: 4096,
            vcpus: 4,
        };
        assert!(snap.fits_on_host(&host));
    }

    #[test]
    fn memory_shape_too_large() {
        let snap = MemoryShape {
            memory_mb: 8192,
            vcpus: 8,
        };
        let host = MemoryShape {
            memory_mb: 4096,
            vcpus: 4,
        };
        assert!(!snap.fits_on_host(&host));
    }

    #[test]
    fn device_model_compatible() {
        let snap = DeviceModel {
            machine_type: "q35".into(),
            config_version: Some("1.0".into()),
            required_devices: vec!["virtio-net".into(), "virtio-blk".into()],
        };
        let host = DeviceModel {
            machine_type: "q35".into(),
            config_version: Some("1.0".into()),
            required_devices: vec![
                "virtio-net".into(),
                "virtio-blk".into(),
                "virtio-rng".into(),
            ],
        };
        assert!(snap.is_compatible_with(&host));
    }

    #[test]
    fn device_model_incompatible_machine_type() {
        let snap = DeviceModel::new("q35");
        let host = DeviceModel::new("pc");
        assert!(!snap.is_compatible_with(&host));
    }

    #[test]
    fn backend_record_same_family() {
        let snap = BackendRecord {
            backend_type: "firecracker".into(),
            backend_version: "1.10.0".into(),
            protocol_version: "2.0".into(),
            guest_agent_version: Some("0.5.0".into()),
        };
        assert!(snap.is_same_family("firecracker"));
        assert!(!snap.is_same_family("qemu"));
    }

    #[test]
    fn backend_record_version_compatible() {
        let snap = BackendRecord {
            backend_type: "firecracker".into(),
            backend_version: "1.10.0".into(),
            protocol_version: "2.0".into(),
            guest_agent_version: None,
        };
        assert!(snap.is_version_compatible("1.10.0"));
        assert!(!snap.is_version_compatible("1.9.0"));
    }

    #[test]
    fn shape_serde_roundtrip() {
        let snap = CpuShape {
            architecture: "x86_64".into(),
            vendor: Some("Intel".into()),
            template: Some("T2".into()),
            required_features: vec!["sse4_2".into()],
        };
        let json = serde_json::to_string(&snap).unwrap();
        let back: CpuShape = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, back);
    }
}

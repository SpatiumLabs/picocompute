use crate::error::ImageError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BootVariant {
    Debug,
    Production,
}

impl std::str::FromStr for BootVariant {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "debug" => Ok(BootVariant::Debug),
            "production" | "prod" => Ok(BootVariant::Production),
            other => Err(format!("unknown boot variant: {other}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelConfigProfile {
    pub profile_id: String,
    pub variant: BootVariant,
    pub architecture: String,
    pub backend: String,
    pub kernel_version: String,
    pub cmdline: String,
    #[serde(default)]
    pub base_options: Vec<String>,
    #[serde(default)]
    pub debug_options: Vec<String>,
}

impl KernelConfigProfile {
    pub fn all_required_options(&self) -> Vec<String> {
        let mut opts = self.base_options.clone();
        match self.variant {
            BootVariant::Debug => opts.extend(self.debug_options.clone()),
            BootVariant::Production => {}
        }
        opts.sort();
        opts.dedup();
        opts
    }

    pub fn validate_config(&self, active_options: &[String]) -> Result<Vec<String>, ImageError> {
        let required = self.all_required_options();
        let active_set: hashbrown::HashSet<&str> =
            active_options.iter().map(|s| s.as_str()).collect();

        let missing: Vec<String> = required
            .iter()
            .filter(|opt| !active_set.contains(opt.as_str()))
            .cloned()
            .collect();

        if !missing.is_empty() {
            return Err(ImageError::KernelConfigValidationFailed {
                profile: self.profile_id.clone(),
                missing_options: missing,
            });
        }

        Ok(required)
    }
}

pub fn firecracker_aarch64_v1() -> KernelConfigProfile {
    KernelConfigProfile {
        profile_id: "firecracker-aarch64-v1".into(),
        variant: BootVariant::Production,
        architecture: "aarch64".into(),
        backend: "firecracker".into(),
        kernel_version: "pico-linux-6.18".into(),
        cmdline: "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw init=/init nomodules"
            .into(),
        base_options: vec![
            "CONFIG_VIRTIO=y".into(),
            "CONFIG_VIRTIO_MMIO=y".into(),
            "CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES=y".into(),
            "CONFIG_VIRTIO_BLK=y".into(),
            "CONFIG_VIRTIO_NET=y".into(),
            "CONFIG_VIRTIO_VSOCKETS=y".into(),
            "CONFIG_VSOCKETS=y".into(),
            "CONFIG_EXT4_FS=y".into(),
            "CONFIG_DEVTMPFS=y".into(),
            "CONFIG_DEVTMPFS_MOUNT=y".into(),
            "CONFIG_NET=y".into(),
            "CONFIG_INET=y".into(),
            "CONFIG_PROC_FS=y".into(),
            "CONFIG_SYSFS=y".into(),
            "CONFIG_TMPFS=y".into(),
        ],
        debug_options: vec![
            "CONFIG_DEBUG_KERNEL=y".into(),
            "CONFIG_DEBUG_INFO=y".into(),
            "CONFIG_DEBUG_FS=y".into(),
            "CONFIG_PRINTK_TIME=y".into(),
            "CONFIG_EARLY_PRINTK=y".into(),
        ],
    }
}

pub fn firecracker_x86_64_v1() -> KernelConfigProfile {
    KernelConfigProfile {
        profile_id: "firecracker-x86_64-v1".into(),
        variant: BootVariant::Production,
        architecture: "x86_64".into(),
        backend: "firecracker".into(),
        kernel_version: "pico-linux-6.18".into(),
        cmdline: "console=ttyS0 noapic reboot=k panic=1 root=/dev/vda rw init=/init nomodules"
            .into(),
        base_options: vec![
            "CONFIG_VIRTIO=y".into(),
            "CONFIG_VIRTIO_PCI=y".into(),
            "CONFIG_VIRTIO_BLK=y".into(),
            "CONFIG_VIRTIO_NET=y".into(),
            "CONFIG_VIRTIO_VSOCKETS=y".into(),
            "CONFIG_VSOCKETS=y".into(),
            "CONFIG_ACPI=y".into(),
            "CONFIG_PCI=y".into(),
            "CONFIG_PCI_MSI=y".into(),
            "CONFIG_KVM_GUEST=y".into(),
            "CONFIG_EXT4_FS=y".into(),
            "CONFIG_DEVTMPFS=y".into(),
            "CONFIG_DEVTMPFS_MOUNT=y".into(),
            "CONFIG_NET=y".into(),
            "CONFIG_INET=y".into(),
            "CONFIG_PROC_FS=y".into(),
            "CONFIG_SYSFS=y".into(),
            "CONFIG_TMPFS=y".into(),
        ],
        debug_options: vec![
            "CONFIG_DEBUG_KERNEL=y".into(),
            "CONFIG_DEBUG_INFO=y".into(),
            "CONFIG_DEBUG_FS=y".into(),
            "CONFIG_PRINTK_TIME=y".into(),
            "CONFIG_EARLY_PRINTK=y".into(),
        ],
    }
}

pub fn qemu_aarch64_v1() -> KernelConfigProfile {
    KernelConfigProfile {
        profile_id: "qemu-aarch64-v1".into(),
        variant: BootVariant::Production,
        architecture: "aarch64".into(),
        backend: "qemu".into(),
        kernel_version: "pico-linux-6.18".into(),
        cmdline: "console=ttyAMA0 reboot=k panic=1 root=/dev/vda rw init=/init nomodules".into(),
        base_options: vec![
            "CONFIG_VIRTIO=y".into(),
            "CONFIG_VIRTIO_PCI=y".into(),
            "CONFIG_VIRTIO_BLK=y".into(),
            "CONFIG_VIRTIO_NET=y".into(),
            "CONFIG_VIRTIO_VSOCKETS=y".into(),
            "CONFIG_VSOCKETS=y".into(),
            "CONFIG_EXT4_FS=y".into(),
            "CONFIG_DEVTMPFS=y".into(),
            "CONFIG_DEVTMPFS_MOUNT=y".into(),
            "CONFIG_PCI=y".into(),
            "CONFIG_PCI_HOST_GENERIC=y".into(),
            "CONFIG_SERIAL_AMBA_PL011=y".into(),
            "CONFIG_NET=y".into(),
            "CONFIG_INET=y".into(),
            "CONFIG_PROC_FS=y".into(),
            "CONFIG_SYSFS=y".into(),
            "CONFIG_TMPFS=y".into(),
        ],
        debug_options: vec![
            "CONFIG_DEBUG_KERNEL=y".into(),
            "CONFIG_DEBUG_INFO=y".into(),
            "CONFIG_DEBUG_FS=y".into(),
            "CONFIG_PRINTK_TIME=y".into(),
            "CONFIG_EARLY_PRINTK=y".into(),
        ],
    }
}

pub fn qemu_x86_64_v1() -> KernelConfigProfile {
    KernelConfigProfile {
        profile_id: "qemu-x86_64-v1".into(),
        variant: BootVariant::Production,
        architecture: "x86_64".into(),
        backend: "qemu".into(),
        kernel_version: "pico-linux-6.18".into(),
        cmdline: "console=ttyS0 noapic reboot=k panic=1 root=/dev/vda rw init=/init nomodules"
            .into(),
        base_options: vec![
            "CONFIG_VIRTIO=y".into(),
            "CONFIG_VIRTIO_PCI=y".into(),
            "CONFIG_VIRTIO_BLK=y".into(),
            "CONFIG_VIRTIO_NET=y".into(),
            "CONFIG_VIRTIO_VSOCKETS=y".into(),
            "CONFIG_VSOCKETS=y".into(),
            "CONFIG_EXT4_FS=y".into(),
            "CONFIG_DEVTMPFS=y".into(),
            "CONFIG_DEVTMPFS_MOUNT=y".into(),
            "CONFIG_PCI=y".into(),
            "CONFIG_KVM_GUEST=y".into(),
            "CONFIG_NET=y".into(),
            "CONFIG_INET=y".into(),
            "CONFIG_PROC_FS=y".into(),
            "CONFIG_SYSFS=y".into(),
            "CONFIG_TMPFS=y".into(),
        ],
        debug_options: vec![
            "CONFIG_DEBUG_KERNEL=y".into(),
            "CONFIG_DEBUG_INFO=y".into(),
            "CONFIG_DEBUG_FS=y".into(),
            "CONFIG_PRINTK_TIME=y".into(),
            "CONFIG_EARLY_PRINTK=y".into(),
        ],
    }
}

pub fn all_profiles() -> Vec<KernelConfigProfile> {
    vec![
        firecracker_aarch64_v1(),
        firecracker_x86_64_v1(),
        qemu_aarch64_v1(),
        qemu_x86_64_v1(),
    ]
}

pub fn find_profile(profile_id: &str) -> Option<KernelConfigProfile> {
    // Historical IDs omitted the underscore in `x86_64`. Keep them as
    // aliases so existing definitions resolve to the ADR profile id.
    let canonical = match profile_id {
        "firecracker-x8664-v1" => "firecracker-x86_64-v1",
        "qemu-x8664-v1" => "qemu-x86_64-v1",
        other => other,
    };
    all_profiles()
        .into_iter()
        .find(|p| p.profile_id == canonical)
}

pub fn kernel_cmdline(arch: &str, backend: &str) -> String {
    let profile_id = format!("{backend}-{arch}-v1");
    find_profile(&profile_id)
        .map(|p| p.cmdline)
        .unwrap_or_else(|| match arch {
            "aarch64" => match backend {
                "qemu" => {
                    "console=ttyAMA0 reboot=k panic=1 root=/dev/vda rw init=/init nomodules".into()
                }
                _ => "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw init=/init nomodules"
                    .into(),
            },
            "x86_64" => {
                "console=ttyS0 noapic reboot=k panic=1 root=/dev/vda rw init=/init nomodules".into()
            }
            _ => "console=ttyS0 reboot=k panic=1 root=/dev/vda rw init=/init nomodules".into(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_variant_includes_debug_options() {
        let mut profile = firecracker_aarch64_v1();
        profile.variant = BootVariant::Debug;
        let all = profile.all_required_options();
        assert!(all.contains(&"CONFIG_DEBUG_KERNEL=y".into()));
        assert!(all.contains(&"CONFIG_DEBUG_INFO=y".into()));
        assert!(all.contains(&"CONFIG_EARLY_PRINTK=y".into()));
    }

    #[test]
    fn production_variant_excludes_debug_options() {
        let profile = firecracker_aarch64_v1();
        let all = profile.all_required_options();
        assert!(!all.contains(&"CONFIG_DEBUG_KERNEL=y".into()));
        assert!(!all.contains(&"CONFIG_EARLY_PRINTK=y".into()));
    }

    #[test]
    fn validate_accepts_matching_config() {
        let profile = firecracker_aarch64_v1();
        let required = profile.all_required_options();
        let result = profile.validate_config(&required);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_rejects_missing_virtio_blk() {
        let profile = firecracker_aarch64_v1();
        let mut opts = profile.all_required_options();
        opts.retain(|o| o != "CONFIG_VIRTIO_BLK=y");
        let result = profile.validate_config(&opts);
        assert!(result.is_err());
    }

    #[test]
    fn validate_rejects_missing_vsock() {
        let profile = firecracker_aarch64_v1();
        let mut opts = profile.all_required_options();
        opts.retain(|o| o != "CONFIG_VIRTIO_VSOCKETS=y");
        let result = profile.validate_config(&opts);
        assert!(result.is_err());
    }

    #[test]
    fn validate_reports_all_missing_options() {
        let profile = firecracker_aarch64_v1();
        let opts: Vec<String> = vec![];
        let result = profile.validate_config(&opts);
        assert!(result.is_err());
        match result {
            Err(ImageError::KernelConfigValidationFailed {
                missing_options, ..
            }) => {
                assert!(missing_options.len() > 1);
                assert!(missing_options.contains(&"CONFIG_VIRTIO_BLK=y".into()));
            }
            _ => panic!("expected KernelConfigValidationFailed"),
        }
    }

    #[test]
    fn firecracker_aarch64_requires_mmio() {
        let profile = firecracker_aarch64_v1();
        let all = profile.all_required_options();
        assert!(all.contains(&"CONFIG_VIRTIO_MMIO=y".into()));
        assert!(all.contains(&"CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES=y".into()));
    }

    #[test]
    fn firecracker_x8664_requires_pci_and_kvm() {
        let profile = firecracker_x86_64_v1();
        let all = profile.all_required_options();
        assert!(all.contains(&"CONFIG_VIRTIO_PCI=y".into()));
        assert!(all.contains(&"CONFIG_PCI=y".into()));
        assert!(all.contains(&"CONFIG_KVM_GUEST=y".into()));
    }

    #[test]
    fn all_profiles_have_required_device_support() {
        for profile in all_profiles() {
            let all = profile.all_required_options();
            assert!(
                all.contains(&"CONFIG_VIRTIO_BLK=y".into()),
                "{} missing VIRTIO_BLK",
                profile.profile_id
            );
            assert!(
                all.contains(&"CONFIG_VIRTIO_NET=y".into()),
                "{} missing VIRTIO_NET",
                profile.profile_id
            );
            assert!(
                all.contains(&"CONFIG_VSOCKETS=y".into()),
                "{} missing VSOCKETS",
                profile.profile_id
            );
            assert!(
                all.contains(&"CONFIG_VIRTIO_VSOCKETS=y".into()),
                "{} missing VIRTIO_VSOCKETS",
                profile.profile_id
            );
            assert!(
                all.contains(&"CONFIG_EXT4_FS=y".into()),
                "{} missing EXT4_FS",
                profile.profile_id
            );
            assert!(
                all.contains(&"CONFIG_DEVTMPFS=y".into()),
                "{} missing DEVTMPFS",
                profile.profile_id
            );
            assert!(
                all.contains(&"CONFIG_NET=y".into()),
                "{} missing NET",
                profile.profile_id
            );
            assert!(
                all.contains(&"CONFIG_INET=y".into()),
                "{} missing INET",
                profile.profile_id
            );
        }
    }

    #[test]
    fn find_profile_by_id() {
        assert!(find_profile("firecracker-aarch64-v1").is_some());
        assert!(find_profile("firecracker-x86_64-v1").is_some());
        assert!(find_profile("qemu-aarch64-v1").is_some());
        assert!(find_profile("qemu-x86_64-v1").is_some());
        assert_eq!(
            find_profile("firecracker-x8664-v1").unwrap().profile_id,
            "firecracker-x86_64-v1"
        );
        assert_eq!(
            find_profile("qemu-x8664-v1").unwrap().profile_id,
            "qemu-x86_64-v1"
        );
        assert!(find_profile("nonexistent").is_none());
    }

    #[test]
    fn kernel_cmdline_x86_64_matches_canonical_profile() {
        let cmd = kernel_cmdline("x86_64", "firecracker");
        let profile = find_profile("firecracker-x86_64-v1").unwrap();
        assert_eq!(cmd, profile.cmdline);
        let qemu = kernel_cmdline("x86_64", "qemu");
        assert_eq!(qemu, find_profile("qemu-x86_64-v1").unwrap().cmdline);
    }

    #[test]
    fn kernel_cmdline_is_not_empty() {
        let cmd = kernel_cmdline("aarch64", "firecracker");
        assert!(!cmd.is_empty());
        assert!(cmd.contains("init=/init"));
    }

    #[test]
    fn boot_variant_parsing() {
        assert_eq!("debug".parse::<BootVariant>().unwrap(), BootVariant::Debug);
        assert_eq!(
            "production".parse::<BootVariant>().unwrap(),
            BootVariant::Production
        );
        assert_eq!(
            "prod".parse::<BootVariant>().unwrap(),
            BootVariant::Production
        );
        assert!("invalid".parse::<BootVariant>().is_err());
    }

    #[test]
    fn debug_variants_are_separate_from_production() {
        let prod = firecracker_aarch64_v1();
        let mut debug = firecracker_aarch64_v1();
        debug.variant = BootVariant::Debug;

        assert!(
            !prod
                .all_required_options()
                .contains(&"CONFIG_DEBUG_KERNEL=y".into())
        );
        assert!(
            debug
                .all_required_options()
                .contains(&"CONFIG_DEBUG_KERNEL=y".into())
        );
    }
}

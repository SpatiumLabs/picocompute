//! Firecracker runtime configuration and environment-derived defaults.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use pico_network_agent::identity::{BackendClass, SandboxNetworkIdentity};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    Aarch64,
    X8664,
}

impl Architecture {
    pub fn detect() -> Self {
        match std::env::consts::ARCH {
            "aarch64" => Architecture::Aarch64,
            "x86_64" => Architecture::X8664,
            other => panic!("unsupported architecture: {other}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct KernelConfig {
    pub image_path: PathBuf,
    pub cmdline: String,
    pub required_config_options: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkConfig {
    pub tap_name: String,
    pub host_ip: Ipv4Addr,
    pub guest_ip: Ipv4Addr,
    pub guest_mac: String,
    pub prefix_len: u8,
}

impl NetworkConfig {
    /// Derives guest-facing network fields from [`SandboxNetworkIdentity`].
    #[must_use]
    pub fn from_identity(identity: &SandboxNetworkIdentity) -> Self {
        Self {
            tap_name: identity.if_name.clone(),
            host_ip: identity.host_ip,
            guest_ip: identity.guest_ip,
            guest_mac: identity.guest_mac.clone(),
            prefix_len: identity.prefix_len,
        }
    }

    #[must_use]
    pub fn for_sandbox_id(sandbox_id: &str) -> Self {
        Self::from_identity(&SandboxNetworkIdentity::for_sandbox(
            sandbox_id,
            BackendClass::MicroVm,
        ))
    }
}

#[derive(Debug, Clone, Default)]
pub struct JailerHardening {
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub chroot_base_dir: Option<PathBuf>,
    pub seccomp_level: Option<u32>,
}

const NOBODY_UID: u32 = 65534;
const NOBODY_GID: u32 = 65534;

impl JailerHardening {
    #[must_use]
    pub fn production_defaults(chroot_base_dir: PathBuf) -> Self {
        Self {
            uid: Some(NOBODY_UID),
            gid: Some(NOBODY_GID),
            chroot_base_dir: Some(chroot_base_dir),
            seccomp_level: Some(2),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.uid.is_some()
            || self.gid.is_some()
            || self.chroot_base_dir.is_some()
            || self.seccomp_level.is_some()
    }
}

#[derive(Debug, Clone)]
pub struct FirecrackerConfig {
    pub arch: Architecture,
    pub firecracker_binary_path: PathBuf,
    pub jailer_binary_path: Option<PathBuf>,
    pub jailer_hardening: JailerHardening,
    pub api_socket_dir: PathBuf,
    pub rootfs_path: PathBuf,
    pub initrd_path: Option<PathBuf>,
    pub guest_agent_addr: SocketAddr,
    pub kernel: KernelConfig,
    pub cpu_template: Option<String>,
    pub mem_size_mib: u32,
    pub vcpu_count: u32,
    pub vsock_guest_cid: Option<u32>,
    pub enable_rng: bool,
    pub validate_paths: bool,
}

impl FirecrackerConfig {
    pub fn detect_defaults() -> Self {
        Self::defaults_for_arch(Architecture::detect())
    }

    fn defaults_for_arch(arch: Architecture) -> Self {
        let jailer_hardening = default_jailer_hardening();
        match arch {
            Architecture::Aarch64 => Self {
                arch,
                firecracker_binary_path: firecracker_binary_path(),
                jailer_binary_path: jailer_binary_path(),
                jailer_hardening,
                api_socket_dir: api_socket_dir(),
                rootfs_path: rootfs_path(),
                initrd_path: initrd_path(),
                guest_agent_addr: guest_agent_addr(),
                kernel: KernelConfig {
                    image_path: kernel_image_path(Architecture::Aarch64),
                    cmdline:
                        "console=ttyS0 noapic reboot=k panic=1 pci=off root=/dev/vda rw init=/init nomodules"
                            .into(),
                    required_config_options: vec![
                        "CONFIG_VIRTIO=y".into(),
                        "CONFIG_VIRTIO_MMIO=y".into(),
                        "CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES=y".into(),
                        "CONFIG_VIRTIO_BLK=y".into(),
                    ],
                },
                cpu_template: None,
                mem_size_mib: 256,
                vcpu_count: 1,
                vsock_guest_cid: Some(3),
                enable_rng: true,
                validate_paths: true,
            },
            Architecture::X8664 => Self {
                arch,
                firecracker_binary_path: firecracker_binary_path(),
                jailer_binary_path: jailer_binary_path(),
                jailer_hardening,
                api_socket_dir: api_socket_dir(),
                rootfs_path: rootfs_path(),
                initrd_path: initrd_path(),
                guest_agent_addr: guest_agent_addr(),
                kernel: KernelConfig {
                    image_path: kernel_image_path(Architecture::X8664),
                    cmdline:
                        "console=ttyS0 noapic reboot=k panic=1 root=/dev/vda rw init=/init nomodules"
                            .into(),
                    required_config_options: vec![
                        "CONFIG_VIRTIO=y".into(),
                        "CONFIG_VIRTIO_PCI=y".into(),
                        "CONFIG_VIRTIO_BLK=y".into(),
                        "CONFIG_ACPI=y".into(),
                        "CONFIG_PCI=y".into(),
                        "CONFIG_PCI_MSI=y".into(),
                        "CONFIG_KVM_GUEST=y".into(),
                    ],
                },
                cpu_template: cpu_template_override().or(None),
                mem_size_mib: 256,
                vcpu_count: 1,
                vsock_guest_cid: Some(3),
                enable_rng: true,
                validate_paths: true,
            },
        }
    }
}

fn firecracker_binary_path() -> PathBuf {
    std::env::var_os("PICO_FIRECRACKER_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("firecracker"))
}

fn api_socket_dir() -> PathBuf {
    std::env::var_os("PICO_FIRECRACKER_SOCKET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
}

fn rootfs_path() -> PathBuf {
    std::env::var_os("PICO_ROOTFS_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/opt/pico/rootfs.ext4"))
}

fn kernel_image_path(arch: Architecture) -> PathBuf {
    if let Some(path) = std::env::var_os("PICO_FIRECRACKER_KERNEL_PATH") {
        return PathBuf::from(path);
    }
    let arch_dir = match arch {
        Architecture::Aarch64 => "aarch64",
        Architecture::X8664 => "x86_64",
    };
    PathBuf::from("/opt/pico/kernel")
        .join(arch_dir)
        .join("vmlinux")
}

fn cpu_template_override() -> Option<String> {
    std::env::var("PICO_FIRECRACKER_CPU_TEMPLATE")
        .ok()
        .filter(|v| !v.is_empty())
}

fn guest_agent_addr() -> SocketAddr {
    std::env::var("PICO_GUEST_AGENT_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:9999".into())
        .parse()
        .expect("PICO_GUEST_AGENT_ADDR must be a socket address")
}

fn initrd_path() -> Option<PathBuf> {
    std::env::var_os("PICO_INITRD_PATH").map(PathBuf::from)
}

fn jailer_binary_path() -> Option<PathBuf> {
    std::env::var_os("PICO_FIRECRACKER_JAILER_BIN").map(PathBuf::from)
}

fn default_jailer_hardening() -> JailerHardening {
    let uid = std::env::var("PICO_JAILER_UID")
        .ok()
        .and_then(|v| v.parse().ok());
    let gid = std::env::var("PICO_JAILER_GID")
        .ok()
        .and_then(|v| v.parse().ok());
    let chroot_base_dir = std::env::var_os("PICO_JAILER_CHROOT_BASE_DIR").map(PathBuf::from);
    let seccomp_level = std::env::var("PICO_JAILER_SECCOMP_LEVEL")
        .ok()
        .and_then(|v| v.parse().ok());
    JailerHardening {
        uid,
        gid,
        chroot_base_dir,
        seccomp_level,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_returns_current_arch() {
        let arch = Architecture::detect();
        #[cfg(target_arch = "aarch64")]
        assert_eq!(arch, Architecture::Aarch64);
        #[cfg(target_arch = "x86_64")]
        assert_eq!(arch, Architecture::X8664);
    }

    #[test]
    fn detect_defaults_returns_valid_config() {
        let cfg = FirecrackerConfig::detect_defaults();
        #[cfg(target_arch = "aarch64")]
        assert_eq!(cfg.arch, Architecture::Aarch64);
        #[cfg(target_arch = "x86_64")]
        assert_eq!(cfg.arch, Architecture::X8664);
        assert!(cfg.kernel.image_path.to_string_lossy().contains("vmlinux"));
        assert!(!cfg.kernel.cmdline.is_empty());
        assert!(!cfg.kernel.required_config_options.is_empty());
        assert!(cfg.cpu_template.is_none());
        assert!(cfg.enable_rng);
        assert_eq!(cfg.vsock_guest_cid, Some(3));
        assert!(cfg.initrd_path.is_none());
    }

    #[test]
    fn kernel_config_options_match_spec() {
        let arm_cfg = FirecrackerConfig::defaults_for_arch(Architecture::Aarch64);
        assert_eq!(
            arm_cfg.kernel.required_config_options,
            vec![
                "CONFIG_VIRTIO=y",
                "CONFIG_VIRTIO_MMIO=y",
                "CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES=y",
                "CONFIG_VIRTIO_BLK=y",
            ]
        );

        let x86_cfg = FirecrackerConfig::defaults_for_arch(Architecture::X8664);
        assert_eq!(
            x86_cfg.kernel.required_config_options,
            vec![
                "CONFIG_VIRTIO=y",
                "CONFIG_VIRTIO_PCI=y",
                "CONFIG_VIRTIO_BLK=y",
                "CONFIG_ACPI=y",
                "CONFIG_PCI=y",
                "CONFIG_PCI_MSI=y",
                "CONFIG_KVM_GUEST=y",
            ]
        );
        assert!(!x86_cfg.kernel.cmdline.contains("pci=off"));
    }

    #[test]
    fn kernel_image_path_contains_arch() {
        let cfg = FirecrackerConfig::detect_defaults();
        let path = cfg.kernel.image_path.to_string_lossy();
        match cfg.arch {
            Architecture::Aarch64 => assert!(path.contains("aarch64")),
            Architecture::X8664 => assert!(path.contains("x86_64")),
        }
    }

    #[test]
    fn kernel_image_path_env_override_wins() {
        let saved = std::env::var_os("PICO_FIRECRACKER_KERNEL_PATH");
        // SAFETY: single-threaded test manipulation would race parallel tests,
        // so restore unconditionally afterwards.
        unsafe { std::env::set_var("PICO_FIRECRACKER_KERNEL_PATH", "/tmp/ci-vmlinux") };
        let result = std::panic::catch_unwind(|| kernel_image_path(Architecture::X8664));
        match saved {
            Some(v) => unsafe { std::env::set_var("PICO_FIRECRACKER_KERNEL_PATH", v) },
            None => unsafe { std::env::remove_var("PICO_FIRECRACKER_KERNEL_PATH") },
        }
        assert_eq!(
            result.unwrap(),
            PathBuf::from("/tmp/ci-vmlinux"),
            "explicit kernel path must win over the /opt default"
        );
    }

    #[test]
    fn network_config_is_stable_and_tap_name_is_short() {
        let network = NetworkConfig::for_sandbox_id("sbx_test");
        assert_eq!(network, NetworkConfig::for_sandbox_id("sbx_test"));
        assert!(network.tap_name.len() <= 15);
        assert_eq!(network.prefix_len, 30);
    }

    #[test]
    fn network_config_matches_sandbox_network_identity() {
        let identity = SandboxNetworkIdentity::for_sandbox("sbx_test", BackendClass::MicroVm);
        let network = NetworkConfig::for_sandbox_id("sbx_test");
        assert_eq!(network.tap_name, identity.if_name);
        assert_eq!(network.host_ip, identity.host_ip);
        assert_eq!(network.guest_ip, identity.guest_ip);
        assert_eq!(network.guest_mac, identity.guest_mac);
        assert_eq!(network.prefix_len, identity.prefix_len);
    }
}

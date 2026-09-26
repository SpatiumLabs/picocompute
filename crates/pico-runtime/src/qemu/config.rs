//! QEMU runtime configuration and host-specific default selection.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

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

    fn qemu_binary(self) -> &'static str {
        match self {
            Architecture::Aarch64 => "qemu-system-aarch64",
            Architecture::X8664 => "qemu-system-x86_64",
        }
    }

    fn kernel_arch_dir(self) -> &'static str {
        match self {
            Architecture::Aarch64 => "aarch64",
            Architecture::X8664 => "x86_64",
        }
    }
}

#[derive(Debug, Clone)]
pub struct KernelConfig {
    pub image_path: PathBuf,
    pub cmdline: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum QemuMode {
    #[default]
    Development,
    Production,
}

impl FromStr for QemuMode {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value {
            "development" | "dev" => Ok(Self::Development),
            "production" | "prod" => Ok(Self::Production),
            other => Err(format!("unsupported QEMU mode: {other}")),
        }
    }
}

#[derive(Debug, Clone)]
pub struct QemuConfig {
    pub mode: QemuMode,
    pub arch: Architecture,
    pub qemu_binary_path: PathBuf,
    pub rootfs_path: PathBuf,
    pub validate_paths: bool,
    pub disk_snapshot: bool,
    pub guest_agent_addr: SocketAddr,
    /// Selects the ADR-0003 production transport. When true (production
    /// default), the adapter returns `GuestTransport::Vsock` and QEMU is
    /// launched with a `vhost-vsock-pci` device. When false, the adapter
    /// uses the Unix serial socket (`serial_fallback = true`).
    pub enable_vsock: bool,
    /// Explicit guest CID override. When `None`, the CID is derived
    /// deterministically from the sandbox id so concurrent VMs on one host
    /// do not share a host-global vsock identity.
    pub vsock_guest_cid: Option<u32>,
    /// Reserved PicoCompute guest-agent vsock port (ADR-0003).
    pub vsock_port: u32,
    /// Compatibility fallback only: expose the guest agent through a
    /// backend-owned virtio-serial chardev Unix socket instead of vsock.
    /// Only honored when `enable_vsock` is false. Backends that support
    /// vsock must use vsock.
    pub serial_fallback: bool,
    /// Directory holding per-sandbox virtio-serial chardev sockets.
    pub serial_socket_dir: PathBuf,
    pub kernel: KernelConfig,
    pub accelerator: String,
    pub mem_size_mib: u32,
    pub vcpu_count: u32,
    pub boot_timeout: Duration,
    pub qmp_enabled: bool,
    pub qmp_addr: SocketAddr,
    pub hardening: crate::RuntimeHardening,
}

impl QemuConfig {
    pub fn detect_defaults() -> Self {
        let arch = Architecture::detect();
        let mode = mode();
        let hardening = default_qemu_hardening();
        Self {
            mode,
            arch,
            qemu_binary_path: qemu_binary_path(arch),
            rootfs_path: rootfs_path(),
            validate_paths: validate_paths(),
            disk_snapshot: disk_snapshot(mode),
            guest_agent_addr: guest_agent_addr(),
            enable_vsock: enable_vsock(mode),
            vsock_guest_cid: vsock_guest_cid(),
            vsock_port: vsock_port(),
            serial_fallback: serial_fallback(mode),
            serial_socket_dir: serial_socket_dir(),
            kernel: KernelConfig {
                image_path: kernel_path(arch),
                cmdline: kernel_cmdline(arch),
            },
            accelerator: accelerator(mode),
            mem_size_mib: mem_size_mib(mode),
            vcpu_count: vcpu_count(),
            boot_timeout: boot_timeout(mode),
            qmp_enabled: qmp_enabled(mode),
            qmp_addr: qmp_addr(),
            hardening,
        }
    }

    pub fn validate_for_start(&self) -> std::result::Result<(), String> {
        if self.mode == QemuMode::Production || self.validate_paths {
            if self
                .accelerator
                .split(':')
                .any(|accelerator| accelerator == "tcg")
            {
                return Err("QEMU production mode does not allow TCG acceleration fallback".into());
            }
            if !self.kernel.image_path.exists() {
                return Err(format!(
                    "QEMU kernel image does not exist: {}",
                    self.kernel.image_path.display()
                ));
            }
            if !self.rootfs_path.exists() {
                return Err(format!(
                    "QEMU rootfs does not exist: {}",
                    self.rootfs_path.display()
                ));
            }
        }

        Ok(())
    }

    pub fn command_args_for_guest_agent(
        &self,
        _guest_agent_host_addr: SocketAddr,
        ssh_host_port: Option<u16>,
    ) -> Vec<String> {
        // Guest-agent control traffic never uses hostfwd; it uses vsock or
        // the Unix serial fallback.
        let mut netdev = String::from("user,id=net0");
        if let Some(host_port) = ssh_host_port {
            netdev.push_str(&format!(",hostfwd=tcp:127.0.0.1:{}-:22", host_port));
        }

        let mut args = vec![
            "-machine".into(),
            machine_arg(self.arch, &self.accelerator),
            "-m".into(),
            self.mem_size_mib.to_string(),
            "-smp".into(),
            self.vcpu_count.to_string(),
            "-kernel".into(),
            self.kernel.image_path.display().to_string(),
            "-append".into(),
            self.kernel.cmdline.clone(),
            "-drive".into(),
            drive_arg(&self.rootfs_path, self.disk_snapshot),
            "-netdev".into(),
            netdev,
            "-device".into(),
            "virtio-net-pci,netdev=net0".into(),
            "-display".into(),
            "none".into(),
            "-serial".into(),
            "mon:stdio".into(),
            "-no-reboot".into(),
        ];

        if self.arch == Architecture::Aarch64 {
            args.push("-cpu".into());
            args.push("host".into());
        }

        if self.qmp_enabled {
            let qmp_arg = format!("tcp:{},server=on,wait=off", self.qmp_addr);
            args.push("-qmp".into());
            args.push(qmp_arg);
        }

        args
    }

    pub fn command_args(&self) -> Vec<String> {
        self.command_args_for_guest_agent(self.guest_agent_addr, None)
    }

    /// Guest vsock CID for a sandbox: explicit override or a deterministic
    /// derivation from the sandbox id.
    #[must_use]
    pub fn guest_cid_for_sandbox(&self, sandbox_id: &str) -> u32 {
        self.vsock_guest_cid
            .unwrap_or_else(|| derive_guest_cid(sandbox_id))
    }

    /// Per-sandbox virtio-serial chardev socket path for the gated fallback.
    #[must_use]
    pub fn serial_socket_path(&self, sandbox_id: &str) -> PathBuf {
        self.serial_socket_dir
            .join(format!("{sandbox_id}.serial.sock"))
    }

    /// QEMU device args exposing vsock to the guest (ADR-0003 default).
    #[must_use]
    pub fn vsock_device_args(&self, sandbox_id: &str) -> Vec<String> {
        vec![
            "-device".into(),
            format!(
                "vhost-vsock-pci,guest-cid={}",
                self.guest_cid_for_sandbox(sandbox_id)
            ),
        ]
    }

    /// QEMU device args for the gated virtio-serial compatibility fallback.
    #[must_use]
    pub fn serial_device_args(&self, sandbox_id: &str) -> Vec<String> {
        let path = self.serial_socket_path(sandbox_id);
        vec![
            "-chardev".into(),
            format!(
                "socket,path={},server=on,wait=off,id=pico-agent0",
                path.display()
            ),
            "-device".into(),
            "virtio-serial-pci,id=pico-serial0".into(),
            "-device".into(),
            "virtserialport,bus=pico-serial0.0,chardev=pico-agent0,name=pico.agent.0".into(),
        ]
    }
}

/// Derives a host-global vsock guest CID deterministically from a sandbox id.
///
/// AF_VSOCK CIDs are host-global, so every QEMU VM on one host needs a
/// distinct CID. The derivation maps the sandbox id into
/// `[3, 0xFFFFFFFE]`, avoiding the reserved `VMADDR_CID_ANY` (0 and
/// `u32::MAX`), hypervisor (1), and host (2) identities.
#[must_use]
pub fn derive_guest_cid(sandbox_id: &str) -> u32 {
    const MIN_CID: u32 = 3;
    const MAX_CID: u32 = 0xFFFF_FFFE;
    let digest = blake3::hash(sandbox_id.as_bytes());
    let bytes: [u8; 4] = digest.as_bytes()[..4].try_into().unwrap_or([0; 4]);
    MIN_CID + (u32::from_le_bytes(bytes) % (MAX_CID - MIN_CID + 1))
}

fn mode() -> QemuMode {
    std::env::var("PICO_QEMU_MODE")
        .ok()
        .and_then(|value| QemuMode::from_str(&value).ok())
        .unwrap_or_default()
}

fn qemu_binary_path(arch: Architecture) -> PathBuf {
    std::env::var_os("PICO_QEMU_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(arch.qemu_binary()))
}

fn rootfs_path() -> PathBuf {
    std::env::var_os("PICO_ROOTFS_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/opt/pico/rootfs.ext4"))
}

fn kernel_path(arch: Architecture) -> PathBuf {
    std::env::var_os("PICO_QEMU_KERNEL_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from("/opt/pico/kernel")
                .join(arch.kernel_arch_dir())
                .join("vmlinux")
        })
}

fn kernel_cmdline(arch: Architecture) -> String {
    std::env::var("PICO_QEMU_KERNEL_CMDLINE").unwrap_or_else(|_| match arch {
        Architecture::Aarch64 => {
            "console=ttyAMA0 reboot=k panic=1 root=/dev/vda rw init=/init nomodules".into()
        }
        Architecture::X8664 => {
            "console=ttyS0 noapic reboot=k panic=1 root=/dev/vda rw init=/init nomodules".into()
        }
    })
}

fn validate_paths() -> bool {
    std::env::var("PICO_QEMU_VALIDATE_PATHS")
        .ok()
        .and_then(|value| parse_bool(&value))
        .unwrap_or(false)
}

fn guest_agent_addr() -> SocketAddr {
    std::env::var("PICO_GUEST_AGENT_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:0".into())
        .parse()
        .expect("PICO_GUEST_AGENT_ADDR must be a socket address")
}

/// Reserved PicoCompute guest-agent vsock port shared with Firecracker (ADR-0003).
pub const GUEST_AGENT_VSOCK_PORT: u32 = 52;

fn enable_vsock(mode: QemuMode) -> bool {
    std::env::var("PICO_QEMU_ENABLE_VSOCK")
        .ok()
        .and_then(|value| parse_bool(&value))
        .unwrap_or(match mode {
            // vhost-vsock needs Linux KVM; development (including macOS hvf)
            // uses the Unix serial fallback unless vsock is explicitly
            // opted in.
            QemuMode::Production => true,
            QemuMode::Development => false,
        })
}

fn vsock_guest_cid() -> Option<u32> {
    std::env::var("PICO_QEMU_VSOCK_CID")
        .ok()
        .and_then(|value| value.parse().ok())
}

fn vsock_port() -> u32 {
    std::env::var("PICO_QEMU_VSOCK_PORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(GUEST_AGENT_VSOCK_PORT)
}

fn serial_fallback(mode: QemuMode) -> bool {
    std::env::var("PICO_QEMU_SERIAL_FALLBACK")
        .ok()
        .and_then(|value| parse_bool(&value))
        .unwrap_or(match mode {
            // Development hosts (including macOS hvf without vhost-vsock)
            // default to the Unix serial fallback so the default config
            // attaches without manual opt-in. Production fails closed to
            // vsock unless the fallback is explicitly enabled.
            QemuMode::Development => true,
            QemuMode::Production => false,
        })
}

fn serial_socket_dir() -> PathBuf {
    std::env::var_os("PICO_QEMU_SERIAL_SOCKET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
}

fn qmp_enabled(mode: QemuMode) -> bool {
    std::env::var("PICO_QEMU_QMP_ENABLED")
        .ok()
        .and_then(|value| parse_bool(&value))
        .unwrap_or(match mode {
            QemuMode::Production => true,
            QemuMode::Development => false,
        })
}

fn qmp_addr() -> SocketAddr {
    let port = std::env::var("PICO_QEMU_QMP_PORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0u16);
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn disk_snapshot(mode: QemuMode) -> bool {
    std::env::var("PICO_QEMU_DISK_SNAPSHOT")
        .ok()
        .and_then(|value| parse_bool(&value))
        .unwrap_or(match mode {
            QemuMode::Development => true,
            QemuMode::Production => false,
        })
}

fn parse_bool(value: &str) -> Option<bool> {
    match value {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn accelerator(mode: QemuMode) -> String {
    std::env::var("PICO_QEMU_ACCEL").unwrap_or_else(|_| match mode {
        QemuMode::Development => development_accelerator(),
        QemuMode::Production => production_accelerator(),
    })
}

fn development_accelerator() -> String {
    #[cfg(target_os = "macos")]
    {
        "hvf:tcg".into()
    }
    #[cfg(target_os = "linux")]
    {
        "kvm:tcg".into()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        "tcg".into()
    }
}

fn production_accelerator() -> String {
    #[cfg(target_os = "macos")]
    {
        "hvf".into()
    }
    #[cfg(target_os = "linux")]
    {
        "kvm".into()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        "tcg".into()
    }
}

fn mem_size_mib(mode: QemuMode) -> u32 {
    std::env::var("PICO_QEMU_MEM_MIB")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(match mode {
            QemuMode::Development => 512,
            QemuMode::Production => 1024,
        })
}

fn vcpu_count() -> u32 {
    std::env::var("PICO_QEMU_VCPUS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1)
}

fn boot_timeout(mode: QemuMode) -> Duration {
    let secs = std::env::var("PICO_QEMU_BOOT_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(match mode {
            QemuMode::Development => 30,
            QemuMode::Production => 60,
        });
    Duration::from_secs(secs)
}

fn default_qemu_hardening() -> crate::RuntimeHardening {
    if std::env::var("PICO_QEMU_HARDENING_ENABLED")
        .ok()
        .and_then(|v| parse_bool(&v))
        .unwrap_or(true)
    {
        crate::RuntimeHardening::default()
    } else {
        crate::RuntimeHardening {
            isolate_namespaces: false,
            unshare_mount_namespace: false,
        }
    }
}

fn machine_arg(arch: Architecture, accelerator: &str) -> String {
    match arch {
        Architecture::Aarch64 => format!("virt,accel={accelerator}"),
        Architecture::X8664 => format!("q35,accel={accelerator}"),
    }
}

fn drive_arg(rootfs_path: &std::path::Path, disk_snapshot: bool) -> String {
    let mut arg = format!("file={},if=virtio,format=raw", rootfs_path.display());
    if disk_snapshot {
        arg.push_str(",snapshot=on");
    }
    arg
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> QemuConfig {
        QemuConfig {
            mode: QemuMode::Development,
            arch: Architecture::Aarch64,
            qemu_binary_path: PathBuf::from("qemu-system-aarch64"),
            rootfs_path: PathBuf::from("/tmp/pico-rootfs.ext4"),
            validate_paths: false,
            disk_snapshot: true,
            guest_agent_addr: "127.0.0.1:9999".parse().unwrap(),
            enable_vsock: false,
            vsock_guest_cid: None,
            vsock_port: GUEST_AGENT_VSOCK_PORT,
            serial_fallback: false,
            serial_socket_dir: PathBuf::from("/tmp/pico-qemu-serial-test"),
            kernel: KernelConfig {
                image_path: PathBuf::from("/tmp/pico-vmlinux"),
                cmdline: "console=ttyAMA0".into(),
            },
            accelerator: "hvf:tcg".into(),
            mem_size_mib: 512,
            vcpu_count: 1,
            boot_timeout: Duration::from_secs(30),
            qmp_enabled: true,
            qmp_addr: "127.0.0.1:0".parse().unwrap(),
            hardening: crate::RuntimeHardening::default(),
        }
    }

    #[test]
    fn command_args_omits_guest_agent_hostfwd() {
        // Guest-agent control traffic never uses hostfwd.
        let cfg = test_config();
        let args = cfg.command_args_for_guest_agent("127.0.0.1:49152".parse().unwrap(), None);
        let netdev = args
            .iter()
            .find(|arg| arg.starts_with("user,id=net0"))
            .unwrap();
        assert!(!netdev.contains(":49152-:9999"));
        assert!(!netdev.contains("hostfwd=tcp:127.0.0.1:49152"));
    }

    #[test]
    fn command_args_include_kernel_and_rootfs() {
        let cfg = test_config();
        let args = cfg.command_args();
        assert!(args.contains(&"-kernel".into()));
        assert!(args.contains(&"-drive".into()));
        assert!(args.iter().any(|arg| arg.contains("pico-rootfs.ext4")));
        assert!(args.iter().any(|arg| arg.contains("snapshot=on")));
    }

    #[test]
    fn command_args_omit_disk_snapshot_when_disabled() {
        let mut cfg = test_config();
        cfg.disk_snapshot = false;

        let args = cfg.command_args();

        assert!(!args.iter().any(|arg| arg.contains("snapshot=on")));
    }

    #[test]
    fn qemu_mode_parses_aliases() {
        assert_eq!(
            "development".parse::<QemuMode>().unwrap(),
            QemuMode::Development
        );
        assert_eq!("dev".parse::<QemuMode>().unwrap(), QemuMode::Development);
        assert_eq!(
            "production".parse::<QemuMode>().unwrap(),
            QemuMode::Production
        );
        assert_eq!("prod".parse::<QemuMode>().unwrap(), QemuMode::Production);
        assert!("other".parse::<QemuMode>().is_err());
    }

    #[test]
    fn production_validation_rejects_tcg_fallback() {
        let mut cfg = test_config();
        cfg.mode = QemuMode::Production;
        cfg.accelerator = "kvm:tcg".into();

        let err = cfg.validate_for_start().unwrap_err();
        assert!(err.contains("TCG"));
    }

    #[test]
    fn command_args_include_qmp_when_enabled() {
        let cfg = test_config();
        let args = cfg.command_args_for_guest_agent("127.0.0.1:49152".parse().unwrap(), None);
        let qmp_idx = args.iter().position(|arg| arg == "-qmp").unwrap();
        assert!(args[qmp_idx + 1].starts_with("tcp:127.0.0.1:0"));
    }

    #[test]
    fn command_args_omit_qmp_when_disabled() {
        let mut cfg = test_config();
        cfg.qmp_enabled = false;
        let args = cfg.command_args();
        assert!(!args.contains(&"-qmp".into()));
    }

    #[test]
    fn validation_rejects_missing_paths_when_validate_paths_enabled() {
        let mut cfg = test_config();
        cfg.mode = QemuMode::Development;
        cfg.validate_paths = true;
        cfg.accelerator = "hvf".into();
        cfg.kernel.image_path = PathBuf::from("/tmp/pico-missing-vmlinux");

        let err = cfg.validate_for_start().unwrap_err();
        assert!(err.contains("kernel image"));
    }

    #[test]
    fn production_validation_requires_vm_assets() {
        let mut cfg = test_config();
        cfg.mode = QemuMode::Production;
        cfg.accelerator = production_accelerator();
        cfg.kernel.image_path = PathBuf::from("/tmp/pico-missing-vmlinux");

        let err = cfg.validate_for_start().unwrap_err();
        assert!(err.contains("kernel image"));
    }

    #[test]
    fn qemu_hardening_defaults_enable_isolation() {
        let hardening = crate::RuntimeHardening::default();

        assert!(hardening.isolate_namespaces);
        assert!(hardening.unshare_mount_namespace);
        assert!(hardening.is_enabled());
    }

    #[test]
    fn qemu_hardening_production_defaults_match_defaults() {
        let prod = crate::RuntimeHardening::production_defaults();
        let dev = crate::RuntimeHardening::default();

        assert_eq!(prod.isolate_namespaces, dev.isolate_namespaces);
        assert_eq!(prod.unshare_mount_namespace, dev.unshare_mount_namespace);
    }

    #[test]
    fn guest_agent_hostfwd_never_wired() {
        // Guest-agent control traffic uses vsock or the Unix serial
        // fallback, never hostfwd.
        let mut vsock = test_config();
        vsock.enable_vsock = true;
        let args = vsock.command_args_for_guest_agent("127.0.0.1:49152".parse().unwrap(), None);
        let netdev = args
            .iter()
            .find(|arg| arg.starts_with("user,id=net0"))
            .unwrap();
        assert!(!netdev.contains("hostfwd=tcp:127.0.0.1:49152"));

        let serial = test_config();
        assert!(
            !serial
                .command_args_for_guest_agent("127.0.0.1:49152".parse().unwrap(), None)
                .iter()
                .find(|arg| arg.starts_with("user,id=net0"))
                .unwrap()
                .contains("hostfwd=tcp:127.0.0.1:49152")
        );
    }

    #[test]
    fn vsock_device_args_pin_guest_cid() {
        let mut cfg = test_config();
        cfg.enable_vsock = true;
        cfg.vsock_guest_cid = Some(7);

        let args = cfg.vsock_device_args("sbx_qemu_vsock");
        let idx = args.iter().position(|arg| arg == "-device").unwrap();
        assert_eq!(args[idx + 1], "vhost-vsock-pci,guest-cid=7");
    }

    #[test]
    fn serial_device_args_use_per_sandbox_socket() {
        let cfg = test_config();

        let args = cfg.serial_device_args("sbx_qemu_serial");
        assert!(
            args.iter()
                .any(|arg| arg.contains("sbx_qemu_serial.serial.sock"))
        );
        assert!(args.iter().any(|arg| arg.contains("virtio-serial-pci")));
        assert!(
            args.iter()
                .any(|arg| arg.contains("virtserialport,bus=pico-serial0.0"))
        );
    }

    #[test]
    fn guest_cid_derivation_is_stable_and_reserved_safe() {
        let cfg = test_config();

        let first = cfg.guest_cid_for_sandbox("sbx_qemu_cid");
        let second = cfg.guest_cid_for_sandbox("sbx_qemu_cid");
        assert_eq!(first, second);
        assert!(first >= 3);

        let other = cfg.guest_cid_for_sandbox("sbx_qemu_cid_other");
        assert!(other >= 3);

        let mut pinned = test_config();
        pinned.vsock_guest_cid = Some(11);
        assert_eq!(pinned.guest_cid_for_sandbox("sbx_qemu_cid"), 11);
        assert_eq!(derive_guest_cid(""), derive_guest_cid(""));
    }

    #[test]
    fn qemu_hardening_defaults_enable_isolation_sanity() {
        let hardening = crate::RuntimeHardening {
            isolate_namespaces: false,
            unshare_mount_namespace: false,
        };

        assert!(!hardening.is_enabled());
    }
}

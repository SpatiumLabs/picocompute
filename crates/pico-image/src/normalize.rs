use crate::error::ImageError;
use crate::lock::PackageLock;
use camino::Utf8Path;
use pico_core::mount::{
    CANONICAL_GUEST_LOGS, CANONICAL_RUNTIME_TMP, CANONICAL_SECRETS_TMPFS, CANONICAL_WORKSPACE,
    GUEST_MOUNT_DISCOVERY_PATH, MountClass, MountContract,
};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use tracing::info;

const AGENT_STARTUP_CONFIG_PATH: &str = "etc/pico/agent.toml";
const INIT_SCRIPT_PATH: &str = "etc/pico/init.sh";

pub fn normalize_rootfs(
    lock: &PackageLock,
    base_archive: &Utf8Path,
    guest_agent_path: &Utf8Path,
    work_dir: &Utf8Path,
    source_date_epoch: i64,
    mount_contract: &MountContract,
) -> Result<camino::Utf8PathBuf, ImageError> {
    let rootfs_dir = work_dir.join("rootfs");

    if rootfs_dir.exists() {
        fs::remove_dir_all(&rootfs_dir)?;
    }
    fs::create_dir_all(&rootfs_dir)?;

    info!(?rootfs_dir, "extracting base rootfs");

    let mut child = Command::new("tar")
        .args(["-xzf", base_archive.as_str(), "-C", rootfs_dir.as_str()])
        .spawn()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                ImageError::MissingTool { tool: "tar".into() }
            } else {
                ImageError::IoError(e)
            }
        })?;

    let status = child.wait()?;
    if !status.success() {
        return Err(ImageError::ParseError("tar extraction failed".into()));
    }

    if !lock.packages.is_empty() {
        install_packages(&rootfs_dir, lock)?;
    }

    inject_guest_agent(&rootfs_dir, guest_agent_path)?;

    embed_agent_startup_config(&rootfs_dir)?;

    embed_init_script(&rootfs_dir)?;

    normalize_filesystem(&rootfs_dir, source_date_epoch)?;

    assure_mount_dirs(&rootfs_dir)?;

    validate_secret_paths(&rootfs_dir, mount_contract)?;

    embed_mount_discovery_file(&rootfs_dir, mount_contract)?;

    info!(?rootfs_dir, "rootfs normalized");

    Ok(rootfs_dir)
}

fn install_packages(rootfs_dir: &Utf8Path, lock: &PackageLock) -> Result<(), ImageError> {
    assert_available("apk")?;

    info!("installing packages via apk");

    let resolve_conf = rootfs_dir.join("etc/resolv.conf");
    fs::write(&resolve_conf, "nameserver 1.1.1.1\n")?;

    let mut packages: Vec<&str> = Vec::new();
    for pkg in &lock.packages {
        if !pkg.version.is_empty() {
            packages.push(pkg.name.as_str());
        }
    }

    if packages.is_empty() {
        return Ok(());
    }

    let mut cmd = Command::new("sudo");
    cmd.arg("apk")
        .arg("add")
        .arg("--no-cache")
        .arg("--root")
        .arg(rootfs_dir.as_str())
        .arg("--initdb")
        .args(&packages);

    let status = cmd.status()?;
    if !status.success() {
        return Err(ImageError::ParseError("apk add failed".into()));
    }

    fs::remove_file(&resolve_conf).ok();

    Ok(())
}

fn inject_guest_agent(
    rootfs_dir: &Utf8Path,
    guest_agent_path: &Utf8Path,
) -> Result<(), ImageError> {
    let target_dir = rootfs_dir.join("usr/local/bin");
    fs::create_dir_all(&target_dir)?;

    let target = target_dir.join("pico-agent");

    info!(?guest_agent_path, ?target, "injecting guest agent");

    fs::copy(guest_agent_path, &target)?;

    let mut perms = fs::metadata(&target)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&target, perms)?;

    Ok(())
}

fn normalize_filesystem(rootfs_dir: &Utf8Path, source_date_epoch: i64) -> Result<(), ImageError> {
    info!(source_date_epoch, "normalizing filesystem");

    let files_to_remove = [
        "etc/machine-id",
        "var/lib/dbus/machine-id",
        "etc/ssh/ssh_host_*",
        "var/log/**/*",
        "tmp/**/*",
        "var/tmp/**/*",
        "var/cache/**/*",
    ];

    for pattern in &files_to_remove {
        if pattern.contains('*') {
            let base = Utf8Path::new(pattern);
            if let Some(parent) = base.parent() {
                let full_parent = rootfs_dir.join(parent);
                if let Ok(entries) = fs::read_dir(&full_parent) {
                    for entry in entries.flatten() {
                        let _ = fs::remove_file(entry.path());
                    }
                }
            }
        } else {
            let path = rootfs_dir.join(pattern);
            if path.is_file() {
                fs::remove_file(&path)?;
            }
        }
    }

    normalize_timestamps(rootfs_dir, source_date_epoch)?;
    normalize_ownership(rootfs_dir)?;

    assure_mount_dirs(rootfs_dir)?;

    Ok(())
}

fn normalize_timestamps(rootfs_dir: &Utf8Path, epoch: i64) -> Result<(), ImageError> {
    info!("setting all timestamps to SOURCE_DATE_EPOCH={}", epoch);

    let _epoch_str = epoch.to_string();

    let status = Command::new("find")
        .arg(rootfs_dir.as_str())
        .arg("-exec")
        .arg("touch")
        .arg("-h")
        .arg("-t")
        .arg(format_touch_date(epoch))
        .arg("{}")
        .arg("+")
        .status()?;

    if !status.success() {
        return Err(ImageError::ParseError(
            "timestamp normalization failed".into(),
        ));
    }

    Ok(())
}

fn format_touch_date(epoch: i64) -> String {
    use chrono::TimeZone;
    let dt = chrono::Utc
        .timestamp_opt(epoch, 0)
        .single()
        .unwrap_or_else(|| chrono::Utc.timestamp_opt(0, 0).single().unwrap());
    dt.format("%Y%m%d%H%M.%S").to_string()
}

fn normalize_ownership(rootfs_dir: &Utf8Path) -> Result<(), ImageError> {
    info!("setting ownership to root:root");

    let status = Command::new("sudo")
        .arg("chown")
        .arg("-R")
        .arg("0:0")
        .arg(rootfs_dir.as_str())
        .status()?;

    if !status.success() {
        return Err(ImageError::ParseError(
            "ownership normalization failed".into(),
        ));
    }

    Ok(())
}

fn assure_mount_dirs(rootfs_dir: &Utf8Path) -> Result<(), ImageError> {
    let mount_dirs = [
        CANONICAL_WORKSPACE.trim_start_matches('/'),
        CANONICAL_RUNTIME_TMP.trim_start_matches('/'),
        CANONICAL_SECRETS_TMPFS.trim_start_matches('/'),
        CANONICAL_GUEST_LOGS.trim_start_matches('/'),
    ];

    for dir in &mount_dirs {
        let path = rootfs_dir.join(dir);
        fs::create_dir_all(&path)?;
    }

    Ok(())
}

fn validate_secret_paths(
    rootfs_dir: &Utf8Path,
    mount_contract: &MountContract,
) -> Result<(), ImageError> {
    for entry in &mount_contract.mounts {
        if entry.class == MountClass::Secret {
            let relative = entry.path.trim_start_matches('/');
            let full_path = rootfs_dir.join(relative);

            if !full_path.exists() {
                return Err(ImageError::MountLayoutError(format!(
                    "secret mount path '{}' does not exist in rootfs",
                    entry.path
                )));
            }

            if !full_path.is_dir() {
                return Err(ImageError::ReservedPathNotEmpty {
                    path: entry.path.clone(),
                });
            }

            if !dir_is_empty(full_path.as_std_path())? {
                return Err(ImageError::ReservedPathNotEmpty {
                    path: entry.path.clone(),
                });
            }
        }
    }

    info!("secret path validation passed");

    Ok(())
}

fn dir_is_empty(path: &std::path::Path) -> Result<bool, std::io::Error> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            if !dir_is_empty(&entry.path())? {
                return Ok(false);
            }
        } else {
            return Ok(false);
        }
    }
    Ok(true)
}

fn embed_mount_discovery_file(
    rootfs_dir: &Utf8Path,
    mount_contract: &MountContract,
) -> Result<(), ImageError> {
    let relative = GUEST_MOUNT_DISCOVERY_PATH.trim_start_matches('/');
    let discovery_path = rootfs_dir.join(relative);

    if let Some(parent) = discovery_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let json = serde_json::to_string_pretty(mount_contract).map_err(|e| {
        ImageError::ParseError(format!("failed to serialize mount contract: {}", e))
    })?;

    fs::write(&discovery_path, json)?;

    info!(?discovery_path, "embedded mount discovery file");

    Ok(())
}

pub fn assert_available(tool: &str) -> Result<(), ImageError> {
    let status = Command::new("which")
        .arg(tool)
        .stdout(std::process::Stdio::null())
        .status()?;

    if !status.success() {
        return Err(ImageError::MissingTool { tool: tool.into() });
    }

    Ok(())
}

fn embed_agent_startup_config(rootfs_dir: &Utf8Path) -> Result<(), ImageError> {
    let config_path = rootfs_dir.join(AGENT_STARTUP_CONFIG_PATH);

    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let config = r#"# PicoCompute guest-agent startup configuration
# This file is read by the guest init system to determine
# how the guest-agent binary should be started.

[agent]
binary = "/usr/local/bin/pico-agent"
listen_addr = "0.0.0.0:9999"
restart = "always"
restart_delay_secs = 1

[protocol]
bootstrap = "pico.guest.bootstrap.v1"
version = "1.0"

[boot]
log_path = "/var/log/pico/boot.log"
outcome_path = "/run/pico/tmp/boot-outcome"
"#;

    fs::write(&config_path, config)?;

    let mut perms = fs::metadata(&config_path)?.permissions();
    perms.set_mode(0o644);
    fs::set_permissions(&config_path, perms)?;

    info!(?config_path, "embedded guest-agent startup config");

    Ok(())
}

fn embed_init_script(rootfs_dir: &Utf8Path) -> Result<(), ImageError> {
    let init_path = rootfs_dir.join(INIT_SCRIPT_PATH);

    if let Some(parent) = init_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let script = r#"#!/bin/sh
set -eu

BOOT_LOG="/var/log/pico/boot.log"
BOOT_OUTCOME="/run/pico/tmp/boot-outcome"
AGENT_BIN="/usr/local/bin/pico-agent"

boot_step() {
    echo "[$(date +%s)] $1" >> "$BOOT_LOG"
}

boot_fail() {
    boot_step "BOOT_FAILED: $1"
    echo "FAILED" > "$BOOT_OUTCOME" 2>/dev/null || true
    exit 1
}

mkdir -p /var/log/pico /run/pico/tmp
boot_step "init_started"

[ -r /proc/mounts ] || mount -t proc proc /proc || boot_fail "proc_mount"
boot_step "proc_mounted"

grep -qs ' /dev devtmpfs ' /proc/mounts || mount -t devtmpfs devtmpfs /dev || boot_fail "devtmpfs_mount"
grep -qs ' /dev/pts devpts ' /proc/mounts || { mkdir -p /dev/pts && mount -t devpts devpts /dev/pts; } || true
boot_step "dev_mounted"

grep -qs ' /sys sysfs ' /proc/mounts || mount -t sysfs sysfs /sys || boot_fail "sysfs_mount"
boot_step "sysfs_mounted"

cmdline="$(cat /proc/cmdline)"
cmdline_value() {
  key="$1"
  for part in $cmdline; do
    case "$part" in
      "$key="*) echo "${part#*=}"; return 0 ;;
    esac
  done
  return 1
}

guest_ip="$(cmdline_value pico_guest_ip || true)"
guest_prefix="$(cmdline_value pico_guest_prefix || echo 30)"
host_ip="$(cmdline_value pico_host_ip || true)"

ip link set lo up || true
if [ -n "$guest_ip" ]; then
  ip link set eth0 up || true
  ip addr add "$guest_ip/$guest_prefix" dev eth0 || true
  if [ -n "$host_ip" ]; then
    ip route add default via "$host_ip" dev eth0 || true
  fi
fi
boot_step "networking_configured"

ssh-keygen -A 2>/dev/null || true
mkdir -p /var/run/sshd
/usr/sbin/sshd 2>/dev/null || true

boot_step "ready_for_agent"

if [ -f "$AGENT_BIN" ]; then
    boot_step "agent_present"
else
    boot_fail "guest_agent_missing"
fi

echo "BOOTED $(date +%s)" > "$BOOT_OUTCOME" 2>/dev/null || true
boot_step "boot_complete"

while true; do
  "$AGENT_BIN" || {
    status="$?"
    boot_step "agent_exited status=$status"
    echo "pico-agent exited with status $status" >&2
  }
  sleep 1
done
"#;

    fs::write(&init_path, script)?;

    let mut perms = fs::metadata(&init_path)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&init_path, perms)?;

    info!(?init_path, "embedded init script");

    Ok(())
}

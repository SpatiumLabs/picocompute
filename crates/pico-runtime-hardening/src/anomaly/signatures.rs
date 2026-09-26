use super::types::{AnomalySeverity, AnomalyType};
use crate::ebpf::syscall::{
    SYSCALL_BPF, SYSCALL_CLONE, SYSCALL_KEXEC_LOAD, SYSCALL_MOUNT, SYSCALL_OPEN, SYSCALL_OPENAT,
    SYSCALL_PTRACE, SYSCALL_SETGID, SYSCALL_SETNS, SYSCALL_SETUID, SYSCALL_UNSHARE,
};

const O_ACCMODE: u64 = 0x3;
/// `CLONE_NEWUSER` flag bit used by `clone` / `unshare`.
const CLONE_NEWUSER: u64 = 0x1000_0000;

pub(super) const DANGEROUS_SYSCALLS: &[u32] = &[SYSCALL_PTRACE, SYSCALL_BPF, SYSCALL_KEXEC_LOAD];

pub(super) const PRIVILEGE_SYSCALLS: &[u32] = &[SYSCALL_SETUID, SYSCALL_SETGID];

#[derive(Debug, Clone, Copy)]
pub(super) struct SignatureHit {
    pub anomaly_type: AnomalyType,
    pub severity: AnomalySeverity,
    pub confidence: f64,
    pub detail: &'static str,
}

pub(super) fn is_dangerous_syscall(syscall_nr: u32) -> bool {
    DANGEROUS_SYSCALLS.contains(&syscall_nr)
}

pub(super) fn is_privilege_syscall(syscall_nr: u32) -> bool {
    PRIVILEGE_SYSCALLS.contains(&syscall_nr)
}

pub(super) fn dangerous_first_use_severity(syscall_nr: u32) -> AnomalySeverity {
    match syscall_nr {
        SYSCALL_KEXEC_LOAD => AnomalySeverity::Critical,
        SYSCALL_BPF | SYSCALL_PTRACE => AnomalySeverity::High,
        _ => AnomalySeverity::Medium,
    }
}

/// Container-escape and breakout signatures (v1+).
///
/// Covered patterns:
/// - `setns` from non-init
/// - cgroup `release_agent` path access
/// - write open of `/proc/self/exe`
/// - open of `/proc/*/mem`, `/dev/mem`, `/dev/kmem`
/// - open of `core_pattern` (kernel core dump redirect)
/// - `unshare`/`clone` with `CLONE_NEWUSER` (user-namespace breakout prep)
/// - `mount` of proc/sysfs/cgroup host trees from guest
/// - `kexec_load` (kernel replacement)
///
/// Note: `bpf` is handled as a dangerous first-use / during-learning alert, not
/// a hard escape signature, to avoid flooding legitimate observability workloads.
pub(super) fn match_escape_signature(
    syscall_nr: u32,
    pid: u32,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    path: Option<&str>,
    path2: Option<&str>,
) -> Option<SignatureHit> {
    if syscall_nr == SYSCALL_SETNS && pid != 1 {
        return Some(SignatureHit {
            anomaly_type: AnomalyType::ContainerEscape,
            severity: AnomalySeverity::Critical,
            confidence: 0.9,
            detail: "setns from non-init process (possible nsenter escape)",
        });
    }

    if syscall_nr == SYSCALL_UNSHARE && (arg0 & CLONE_NEWUSER) != 0 {
        return Some(SignatureHit {
            anomaly_type: AnomalyType::ContainerEscape,
            severity: AnomalySeverity::High,
            confidence: 0.75,
            detail: "unshare with CLONE_NEWUSER (user-namespace breakout prep)",
        });
    }

    if syscall_nr == SYSCALL_CLONE && (arg0 & CLONE_NEWUSER) != 0 {
        return Some(SignatureHit {
            anomaly_type: AnomalyType::ContainerEscape,
            severity: AnomalySeverity::High,
            confidence: 0.7,
            detail: "clone with CLONE_NEWUSER (user-namespace breakout prep)",
        });
    }

    if syscall_nr == SYSCALL_KEXEC_LOAD {
        return Some(SignatureHit {
            anomaly_type: AnomalyType::ContainerEscape,
            severity: AnomalySeverity::Critical,
            confidence: 0.95,
            detail: "kexec_load (kernel replacement)",
        });
    }

    if matches!(syscall_nr, SYSCALL_OPEN | SYSCALL_OPENAT)
        && let Some(p) = path
    {
        if path_mentions_release_agent(p) {
            return Some(SignatureHit {
                anomaly_type: AnomalyType::ContainerEscape,
                severity: AnomalySeverity::Critical,
                confidence: 0.95,
                detail: "access to cgroup release_agent path",
            });
        }

        if path_is_proc_self_exe(p) && open_has_write_mode(syscall_nr, arg1, arg2) {
            return Some(SignatureHit {
                anomaly_type: AnomalyType::ContainerEscape,
                severity: AnomalySeverity::Critical,
                confidence: 0.9,
                detail: "write open of /proc/self/exe",
            });
        }

        if path_is_sensitive_mem(p) {
            return Some(SignatureHit {
                anomaly_type: AnomalyType::ContainerEscape,
                severity: AnomalySeverity::Critical,
                confidence: 0.85,
                detail: "open of kernel/process memory device or /proc/*/mem",
            });
        }

        if path_is_core_pattern(p) {
            return Some(SignatureHit {
                anomaly_type: AnomalyType::ContainerEscape,
                severity: AnomalySeverity::Critical,
                confidence: 0.9,
                detail: "access to core_pattern (core dump redirect)",
            });
        }
    }

    if syscall_nr == SYSCALL_MOUNT {
        let src = path.unwrap_or("");
        let tgt = path2.unwrap_or("");
        if mount_targets_host_fs(src, tgt) {
            return Some(SignatureHit {
                anomaly_type: AnomalyType::ContainerEscape,
                severity: AnomalySeverity::High,
                confidence: 0.8,
                detail: "mount of sensitive host filesystem (proc/sys/cgroup)",
            });
        }
    }

    None
}

fn path_mentions_release_agent(path: &str) -> bool {
    path.contains("release_agent")
}

fn path_is_proc_self_exe(path: &str) -> bool {
    path == "/proc/self/exe" || path.ends_with("/proc/self/exe")
}

fn path_is_sensitive_mem(path: &str) -> bool {
    path == "/dev/mem"
        || path == "/dev/kmem"
        || path == "/proc/kcore"
        || path.ends_with("/mem") && path.starts_with("/proc/")
}

fn path_is_core_pattern(path: &str) -> bool {
    path.contains("core_pattern")
}

fn mount_targets_host_fs(src: &str, tgt: &str) -> bool {
    let interesting = |s: &str| {
        s == "proc"
            || s == "sysfs"
            || s == "cgroup"
            || s == "cgroup2"
            || s.starts_with("/proc")
            || s.starts_with("/sys")
            || s.contains("cgroup")
    };
    interesting(src) || interesting(tgt)
}

fn open_has_write_mode(syscall_nr: u32, arg1: u64, arg2: u64) -> bool {
    let flags = match syscall_nr {
        SYSCALL_OPEN => arg1,
        SYSCALL_OPENAT => arg2,
        _ => return false,
    };
    (flags & O_ACCMODE) != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setns_from_non_init_is_escape() {
        let hit = match_escape_signature(SYSCALL_SETNS, 42, 0, 0, 0, None, None);
        assert!(hit.is_some());
    }

    #[test]
    fn setns_from_init_is_not_escape() {
        assert!(match_escape_signature(SYSCALL_SETNS, 1, 0, 0, 0, None, None).is_none());
    }

    #[test]
    fn release_agent_path_is_escape() {
        let hit = match_escape_signature(
            SYSCALL_OPENAT,
            10,
            0,
            0,
            0,
            Some("/sys/fs/cgroup/release_agent"),
            None,
        );
        assert!(hit.is_some());
    }

    #[test]
    fn proc_self_exe_write_is_escape() {
        let hit = match_escape_signature(SYSCALL_OPEN, 10, 0, 1, 0, Some("/proc/self/exe"), None);
        assert!(hit.is_some());
    }

    #[test]
    fn proc_mem_is_escape() {
        let hit = match_escape_signature(SYSCALL_OPEN, 10, 0, 0, 0, Some("/proc/1/mem"), None);
        assert!(hit.is_some());
    }

    #[test]
    fn core_pattern_is_escape() {
        let hit = match_escape_signature(
            SYSCALL_OPEN,
            10,
            0,
            0,
            0,
            Some("/proc/sys/kernel/core_pattern"),
            None,
        );
        assert!(hit.is_some());
    }

    #[test]
    fn unshare_newuser_is_escape() {
        let hit = match_escape_signature(SYSCALL_UNSHARE, 10, CLONE_NEWUSER, 0, 0, None, None);
        assert!(hit.is_some());
    }

    #[test]
    fn mount_proc_is_escape() {
        let hit =
            match_escape_signature(SYSCALL_MOUNT, 10, 0, 0, 0, Some("proc"), Some("/host/proc"));
        assert!(hit.is_some());
    }

    #[test]
    fn dangerous_list_includes_ptrace_bpf_kexec() {
        assert!(is_dangerous_syscall(SYSCALL_PTRACE));
        assert!(is_dangerous_syscall(SYSCALL_BPF));
        assert!(is_dangerous_syscall(SYSCALL_KEXEC_LOAD));
        assert!(!is_dangerous_syscall(SYSCALL_OPEN));
    }
}

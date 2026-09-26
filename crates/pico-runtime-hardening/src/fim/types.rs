//! File integrity monitoring types.

use serde::{Deserialize, Serialize};

/// Operating mode for file integrity enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum FimMode {
    /// Emit alerts only; allow the operation.
    #[default]
    Audit = 0,
    /// Block the operation in the kernel (via BPF LSM) and emit an alert.
    Enforce = 1,
}

impl FimMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Audit => "audit",
            Self::Enforce => "enforce",
        }
    }

    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Enforce,
            _ => Self::Audit,
        }
    }
}

/// LSM hook that produced a file-integrity event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum FimHook {
    FileOpen = 0,
    InodePermission = 1,
    InodeUnlink = 2,
    /// Userspace path from syscall audit (`open`/`openat`).
    SyscallOpen = 3,
}

impl FimHook {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FileOpen => "file_open",
            Self::InodePermission => "inode_permission",
            Self::InodeUnlink => "inode_unlink",
            Self::SyscallOpen => "syscall_open",
        }
    }

    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::FileOpen,
            1 => Self::InodePermission,
            2 => Self::InodeUnlink,
            3 => Self::SyscallOpen,
            _ => Self::FileOpen,
        }
    }
}

/// Process identity carried with a FIM observation or alert.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct FimProcessInfo {
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub gid: u32,
    pub cgroup_id: u64,
    pub timestamp_ns: u64,
}

/// Alert raised when a sandbox touches a protected path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FimAlert {
    pub sandbox_id: String,
    pub path: String,
    pub hook: FimHook,
    pub mode: FimMode,
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub gid: u32,
    pub cgroup_id: u64,
    pub timestamp_ns: u64,
    /// Whether the kernel (or checker) denied the operation.
    pub denied: bool,
    pub detail: String,
}

impl FimAlert {
    pub fn summary(&self) -> String {
        format!(
            "sandbox={} path={} hook={} mode={} pid={} uid={} denied={} detail={}",
            self.sandbox_id,
            self.path,
            self.hook.as_str(),
            self.mode.as_str(),
            self.pid,
            self.uid,
            self.denied,
            self.detail
        )
    }
}

/// Operation intent observed against a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FimOperation {
    /// Write, truncate, create, or append open / MAY_WRITE permission.
    Write,
    /// Unlink / delete of a protected path.
    Unlink,
}

/// Linux open(2)/openat(2) flag bits relevant to write intent.
pub const O_WRONLY: u64 = 0o1;
pub const O_RDWR: u64 = 0o2;
pub const O_CREAT: u64 = 0o100;
pub const O_TRUNC: u64 = 0o1000;
pub const O_APPEND: u64 = 0o2000;

/// `inode_permission` / `file_permission` MAY_WRITE mask bit.
pub const MAY_WRITE: i32 = 0x2;

/// Returns true when open flags indicate a write or mutate intent.
#[must_use]
pub fn open_flags_write_intent(flags: u64) -> bool {
    let accmode = flags & 0o3;
    accmode == O_WRONLY || accmode == O_RDWR || flags & (O_CREAT | O_TRUNC | O_APPEND) != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_flags_detect_write_modes() {
        assert!(!open_flags_write_intent(0)); // O_RDONLY
        assert!(open_flags_write_intent(O_WRONLY));
        assert!(open_flags_write_intent(O_RDWR));
        assert!(open_flags_write_intent(O_CREAT));
        assert!(open_flags_write_intent(O_TRUNC));
        assert!(open_flags_write_intent(O_APPEND));
        assert!(open_flags_write_intent(O_WRONLY | O_CREAT | O_TRUNC));
    }

    #[test]
    fn mode_roundtrip() {
        assert_eq!(FimMode::from_u8(0), FimMode::Audit);
        assert_eq!(FimMode::from_u8(1), FimMode::Enforce);
        assert_eq!(FimMode::Audit.as_str(), "audit");
        assert_eq!(FimMode::Enforce.as_str(), "enforce");
    }
}

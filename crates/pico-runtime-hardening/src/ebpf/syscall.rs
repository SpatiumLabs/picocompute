use serde::{Deserialize, Serialize};

pub const MONITORED_SYSCALL_COUNT: usize = 14;

pub const SYSCALL_OPEN: u32 = 0;
pub const SYSCALL_OPENAT: u32 = 1;
pub const SYSCALL_EXECVE: u32 = 2;
pub const SYSCALL_CONNECT: u32 = 3;
pub const SYSCALL_SENDFILE: u32 = 4;
pub const SYSCALL_UNSHARE: u32 = 5;
pub const SYSCALL_CLONE: u32 = 6;
pub const SYSCALL_PTRACE: u32 = 7;
pub const SYSCALL_MOUNT: u32 = 8;
pub const SYSCALL_BPF: u32 = 9;
pub const SYSCALL_KEXEC_LOAD: u32 = 10;
pub const SYSCALL_SETUID: u32 = 11;
pub const SYSCALL_SETGID: u32 = 12;
pub const SYSCALL_SETNS: u32 = 13;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct SandboxAuditConfig {
    pub enabled: u8,
    pub _pad: [u8; 3],
    pub sample_rate: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct SyscallCountKey {
    pub cgroup_id: u64,
    pub syscall_nr: u32,
    pub _pad: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct RawSyscallEvent {
    pub cgroup_id: u64,
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub gid: u32,
    pub syscall_nr: u32,
    pub timestamp_ns: u64,
    pub arg0: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
    pub retval: i64,
    pub string_buf: [u8; 256],
    pub string_len: u32,
    pub _pad: [u8; 4],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallEvent {
    pub cgroup_id: u64,
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub gid: u32,
    pub syscall_name: String,
    pub syscall_nr: u32,
    pub timestamp_ns: u64,
    pub arg0: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
    pub retval: i64,
    pub string_arg0: Option<String>,
    pub string_arg1: Option<String>,
    pub is_enter: bool,
}

const SYSCALL_NAMES: [(&str, u32); MONITORED_SYSCALL_COUNT] = [
    ("open", SYSCALL_OPEN),
    ("openat", SYSCALL_OPENAT),
    ("execve", SYSCALL_EXECVE),
    ("connect", SYSCALL_CONNECT),
    ("sendfile", SYSCALL_SENDFILE),
    ("unshare", SYSCALL_UNSHARE),
    ("clone", SYSCALL_CLONE),
    ("ptrace", SYSCALL_PTRACE),
    ("mount", SYSCALL_MOUNT),
    ("bpf", SYSCALL_BPF),
    ("kexec_load", SYSCALL_KEXEC_LOAD),
    ("setuid", SYSCALL_SETUID),
    ("setgid", SYSCALL_SETGID),
    ("setns", SYSCALL_SETNS),
];

pub fn syscall_name(nr: u32) -> &'static str {
    for (name, id) in &SYSCALL_NAMES {
        if *id == nr {
            return name;
        }
    }
    "unknown"
}

impl SyscallEvent {
    pub fn from_raw(raw: RawSyscallEvent) -> Self {
        let name = syscall_name(raw.syscall_nr);
        let is_enter = raw.retval == -1;
        let (string_arg0, string_arg1) = if raw.string_len > 0 {
            let data = &raw.string_buf[..raw.string_len as usize];
            let null_pos = data.iter().position(|&b| b == 0);
            match null_pos {
                Some(pos) => {
                    let first = std::str::from_utf8(&data[..pos]).unwrap_or("").to_string();
                    let remaining = &data[pos + 1..];
                    let second = if remaining.is_empty() || remaining[0] == 0 {
                        None
                    } else {
                        let end = remaining
                            .iter()
                            .position(|&b| b == 0)
                            .unwrap_or(remaining.len());
                        std::str::from_utf8(&remaining[..end])
                            .ok()
                            .map(|s| s.to_string())
                    };
                    (Some(first), second)
                }
                None => {
                    let s = std::str::from_utf8(data).unwrap_or("").to_string();
                    (Some(s), None)
                }
            }
        } else {
            (None, None)
        };

        Self {
            cgroup_id: raw.cgroup_id,
            pid: raw.pid,
            tid: raw.tid,
            uid: raw.uid,
            gid: raw.gid,
            syscall_name: name.to_string(),
            syscall_nr: raw.syscall_nr,
            timestamp_ns: raw.timestamp_ns,
            arg0: raw.arg0,
            arg1: raw.arg1,
            arg2: raw.arg2,
            arg3: raw.arg3,
            retval: raw.retval,
            string_arg0,
            string_arg1,
            is_enter,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syscall_name_covers_all_monitored() {
        for i in 0..MONITORED_SYSCALL_COUNT as u32 {
            assert_ne!(syscall_name(i), "unknown");
        }
        assert_eq!(syscall_name(999), "unknown");
    }

    #[test]
    fn from_raw_parses_dual_strings() {
        let mut raw = RawSyscallEvent {
            cgroup_id: 1,
            pid: 2,
            tid: 3,
            uid: 4,
            gid: 5,
            syscall_nr: SYSCALL_MOUNT,
            timestamp_ns: 6,
            arg0: 0,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            retval: -1,
            string_buf: [0u8; 256],
            string_len: 0,
            _pad: [0; 4],
        };
        let s = b"src\0dst\0";
        raw.string_buf[..s.len()].copy_from_slice(s);
        raw.string_len = s.len() as u32;
        let ev = SyscallEvent::from_raw(raw);
        assert_eq!(ev.string_arg0.as_deref(), Some("src"));
        assert_eq!(ev.string_arg1.as_deref(), Some("dst"));
        assert!(ev.is_enter);
    }
}

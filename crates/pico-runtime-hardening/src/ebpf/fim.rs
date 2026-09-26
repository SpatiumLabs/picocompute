//! Shared ABI types for file integrity eBPF maps and ring-buffer events.

/// Max path bytes carried in a ring-buffer FIM event (matches eBPF side).
pub const FIM_MAX_PATH_LEN: usize = 256;

/// Max protected path entries in the global `PROTECTED_PATHS` BPF map.
pub const FIM_MAX_PROTECTED_PATHS: u32 = 4096;

/// Max protected paths installed per sandbox (map hygiene).
pub const FIM_MAX_PATHS_PER_SANDBOX: usize = 64;

/// Max bytes of a single protected path stored in the BPF path map.
/// Paths longer than this are truncated in the BPF key; prefer short prefixes.
pub const FIM_BPF_PATH_KEY_LEN: usize = 128;

/// Ring buffer size for FIM events (bytes).
pub const FIM_RING_BUF_SIZE: u32 = 256 * 1024;

/// Per-sandbox FIM configuration stored in the `FIM_CONFIG` BPF map.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct FimSandboxConfig {
    /// Non-zero when FIM is active for this cgroup.
    pub enabled: u8,
    /// [`crate::fim::FimMode`] as u8 (0 = audit, 1 = enforce).
    pub mode: u8,
    pub _pad: [u8; 6],
}

/// Key for the `PROTECTED_PATHS` map: cgroup + fixed-size path prefix/exact.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct FimPathKey {
    pub cgroup_id: u64,
    pub path: [u8; FIM_BPF_PATH_KEY_LEN],
}

/// Raw ring-buffer event emitted by BPF LSM FIM hooks.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct RawFimEvent {
    pub cgroup_id: u64,
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub gid: u32,
    /// [`crate::fim::FimHook`] as u8.
    pub hook: u8,
    /// Non-zero when the LSM program returned `-EPERM`.
    pub denied: u8,
    pub _pad: [u8; 2],
    pub timestamp_ns: u64,
    pub path_buf: [u8; FIM_MAX_PATH_LEN],
    pub path_len: u32,
    pub _pad2: [u8; 4],
}

impl FimPathKey {
    /// Build a path key from a UTF-8 path, truncating to [`FIM_BPF_PATH_KEY_LEN`].
    #[must_use]
    pub fn from_path(cgroup_id: u64, path: &str) -> Self {
        let mut key = Self {
            cgroup_id,
            path: [0u8; FIM_BPF_PATH_KEY_LEN],
        };
        let bytes = path.as_bytes();
        let len = bytes.len().min(FIM_BPF_PATH_KEY_LEN);
        key.path[..len].copy_from_slice(&bytes[..len]);
        key
    }
}

impl RawFimEvent {
    /// Decode the path buffer as a UTF-8 string (lossy on invalid sequences).
    #[must_use]
    pub fn path_string(&self) -> String {
        if self.path_len == 0 {
            return String::new();
        }
        let len = (self.path_len as usize).min(FIM_MAX_PATH_LEN);
        let data = &self.path_buf[..len];
        let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
        String::from_utf8_lossy(&data[..end]).into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_key_truncates() {
        let long = "a".repeat(FIM_BPF_PATH_KEY_LEN + 40);
        let key = FimPathKey::from_path(1, &long);
        assert_eq!(key.cgroup_id, 1);
        assert_eq!(
            key.path.iter().filter(|&&b| b != 0).count(),
            FIM_BPF_PATH_KEY_LEN
        );
    }

    #[test]
    fn raw_event_path_string() {
        let mut ev = RawFimEvent {
            cgroup_id: 1,
            pid: 2,
            tid: 3,
            uid: 4,
            gid: 5,
            hook: 0,
            denied: 0,
            _pad: [0; 2],
            timestamp_ns: 6,
            path_buf: [0; FIM_MAX_PATH_LEN],
            path_len: 0,
            _pad2: [0; 4],
        };
        let p = b"/etc/passwd";
        ev.path_buf[..p.len()].copy_from_slice(p);
        ev.path_len = p.len() as u32;
        assert_eq!(ev.path_string(), "/etc/passwd");
    }
}

//! File integrity monitoring via BPF LSM hooks and userspace baselines.
//!
//! # Design
//!
//! * **Baseline**: per-sandbox set of protected paths (defaults cover
//!   `/etc/passwd`, system binaries/libraries; can merge image SBOM paths).
//! * **Observation**: BPF LSM hooks (`file_open`, `inode_permission`,
//!   `inode_unlink`) filtered by sandbox cgroup, plus a syscall-audit bridge
//!   for `open`/`openat` write-intent events (primary production path when LSM
//!   path resolution is unavailable).
//! * **Modes**: `audit` (alert only) vs `enforce` (kernel `-EPERM` on
//!   path-bearing protected `file_open` matches only).
//!
//! # Enforcement scope (intentional)
//!
//! Kernel denial is limited to **write-intent `file_open`** when `bpf_d_path`
//! succeeds and the path matches the baseline. `inode_permission` and
//! `inode_unlink` are **audit/correlation only** (path-less fail-open): they
//! never return `-EPERM`. Unlink or rename of a protected path is not blocked
//! by v1 FIM; rely on the syscall-audit open bridge for alerts and on image
//! immutability for stronger integrity.
//!
//! Path resolution uses best-effort `struct file` `f_path` probing at candidate
//! offsets [16, 24, 32] (multi-offset fallback; CO-RE/BTF field access preferred
//! once the eBPF builder pins a vmlinux BTF input). When all offsets fail the
//! LSM path fails open (no deny, empty path event). Path-resolution failures
//! are counted for observability.
//!
//! # Kernel requirements
//!
//! * Linux 5.7+ with `CONFIG_BPF_LSM=y` and host BTF
//! * `bpf` listed in `/sys/kernel/security/lsm` (boot param `lsm=...,bpf`)
//! * Without LSM, userspace checker + syscall-audit bridge still alert in audit mode
//!
//! # Lifecycle
//!
//! ```ignore
//! use pico_runtime_hardening::fim::{
//!     FileIntegrityChecker, FimMode, IntegrityBaseline,
//! };
//!
//! let checker = FileIntegrityChecker::with_defaults();
//! checker.register_sandbox("sb-1", cgroup_id, FimMode::Audit, None);
//! // on destroy:
//! checker.unregister_sandbox("sb-1");
//! ```

mod baseline;
mod checker;
mod types;

pub use baseline::IntegrityBaseline;
pub use checker::{FileIntegrityChecker, FimStats};
pub use types::{
    FimAlert, FimHook, FimMode, FimOperation, FimProcessInfo, MAY_WRITE, O_APPEND, O_CREAT, O_RDWR,
    O_TRUNC, O_WRONLY, open_flags_write_intent,
};

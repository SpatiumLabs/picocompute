//! Behavioral anomaly detection for sandbox syscall streams.
//!
//! Learns per-sandbox-type baselines, then alerts on frequency spikes,
//! dangerous first-use, privilege escalation, and container-escape signatures.
//! v1 is alert-only (no auto-remediation).
//!
//! # Lifecycle integration (required for shared baselines)
//!
//! Callers in the sandbox create path **must** register both the cgroup and a
//! stable type key. Prefer the combined API:
//!
//! ```ignore
//! use pico_runtime_hardening::anomaly::sandbox_type_key;
//! use pico_runtime_hardening::ebpf::EbpfSyscallMonitor;
//!
//! let type_key = sandbox_type_key(image_id, workload_label);
//! monitor.register_sandbox_audit(sandbox_id, cgroup_id, &type_key, true, sample_rate)?;
//! // on destroy:
//! monitor.unregister_sandbox_audit(sandbox_id, cgroup_id)?;
//! ```
//!
//! Without `sandbox_type`, the detector falls back to `cgroup-{id}` keys and
//! **never shares baselines** across sandboxes of the same image/workload.
//!
//! # Escape signatures
//!
//! - `setns` from non-init; `unshare`/`clone` with `CLONE_NEWUSER`
//! - cgroup `release_agent`; write `/proc/self/exe`; `/proc/*/mem`, `/dev/mem`
//! - `core_pattern`; mount of proc/sys/cgroup; `bpf` / `kexec_load`
//!
//! Dangerous first-use / during-learning: `ptrace`, `bpf`, `kexec_load`.
//!
//! # Performance
//!
//! Sandbox state is sharded across 32 mutexes; baselines use a shared
//! `RwLock`. Prefer `sample_rate` under extreme load.

mod baseline;
mod detector;
mod signatures;
mod types;

pub use baseline::{DetectorConfig, TypePrior, sandbox_type_key};
pub use detector::AnomalyDetector;
pub use types::{AnomalyEvent, AnomalySeverity, AnomalyType};

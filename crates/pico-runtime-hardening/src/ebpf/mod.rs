pub mod fim;
pub mod syscall;

use std::sync::Arc;

#[cfg(all(target_os = "linux", feature = "ebpf-syscall-audit"))]
mod linux;
#[cfg(not(all(target_os = "linux", feature = "ebpf-syscall-audit")))]
mod stub;

#[cfg(all(target_os = "linux", feature = "ebpf-file-integrity"))]
mod fim_linux;
#[cfg(not(all(target_os = "linux", feature = "ebpf-file-integrity")))]
mod fim_stub;

#[cfg(all(target_os = "linux", feature = "ebpf-syscall-audit"))]
pub use linux::EbpfSyscallMonitor;
#[cfg(not(all(target_os = "linux", feature = "ebpf-syscall-audit")))]
pub use stub::EbpfSyscallMonitor;

#[cfg(all(target_os = "linux", feature = "ebpf-file-integrity"))]
pub use fim_linux::EbpfFileIntegrityMonitor;
#[cfg(not(all(target_os = "linux", feature = "ebpf-file-integrity")))]
pub use fim_stub::EbpfFileIntegrityMonitor;

/// Optional bridge: called for each syscall audit event with the resolved
/// sandbox id. Shared via [`Arc`] + [`parking_lot::RwLock`] so the host can
/// attach FIM after the consumer has already started.
pub type SyscallFimObserver = Arc<dyn Fn(&str, &syscall::SyscallEvent) + Send + Sync>;

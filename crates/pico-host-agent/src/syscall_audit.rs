//! Host-side lifecycle wiring for eBPF syscall audit + anomaly detection.
//!
//! On sandbox prepare/create the host registers the cgroup and a stable type key
//! (`image:workload`). On destroy it unregisters. Missing eBPF support is
//! non-fatal: registration falls back to userspace-only type association.
//!
//! Call [`Self::set_fim_observer`] after constructing
//! [`crate::file_integrity::FileIntegrityService`] so open/openat write-intent
//! events flow into the FIM checker even when BPF LSM path resolution fails.

use std::sync::Arc;

use parking_lot::Mutex;
use pico_runtime_hardening::ebpf::{EbpfSyscallMonitor, SyscallFimObserver};
use pico_runtime_hardening::{DetectorConfig, sandbox_type_key};
use tokio::sync::watch;
use tracing::{info, warn};

/// Default ringbuf/audit sampling: process every Nth enter (1 = all).
const DEFAULT_SAMPLE_RATE: u32 = 10;

pub struct SyscallAuditService {
    inner: Mutex<Inner>,
    sample_rate: u32,
}

struct Inner {
    monitor: Option<EbpfSyscallMonitor>,
    shutdown_tx: Option<watch::Sender<bool>>,
}

impl SyscallAuditService {
    /// Best-effort start. Returns a service even when eBPF is unavailable so
    /// callers can still register type keys for userspace anomaly state.
    pub fn try_start() -> Arc<Self> {
        let sample_rate = std::env::var("PICO_SYSCALL_AUDIT_SAMPLE_RATE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_SAMPLE_RATE);

        let enabled = std::env::var("PICO_SYSCALL_AUDIT")
            .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
            .unwrap_or(true);

        if !enabled {
            info!("syscall audit disabled via PICO_SYSCALL_AUDIT");
            return Arc::new(Self {
                inner: Mutex::new(Inner {
                    monitor: None,
                    shutdown_tx: None,
                }),
                sample_rate,
            });
        }

        match EbpfSyscallMonitor::load() {
            Ok(mut mon) => {
                let (tx, rx) = watch::channel(false);
                match mon.run_consumer(rx) {
                    Ok((_ring, _consumer)) => {
                        info!(
                            sample_rate,
                            "syscall audit consumer started (eBPF ringbuf path)"
                        );
                    }
                    Err(err) => {
                        // Expected on non-Linux / stub: userspace registration still works.
                        warn!(
                            error = %err,
                            "syscall audit ringbuf consumer unavailable; type registration only"
                        );
                    }
                }
                Arc::new(Self {
                    inner: Mutex::new(Inner {
                        monitor: Some(mon),
                        shutdown_tx: Some(tx),
                    }),
                    sample_rate,
                })
            }
            Err(err) => {
                warn!(error = %err, "syscall audit monitor not loaded");
                Arc::new(Self {
                    inner: Mutex::new(Inner {
                        monitor: None,
                        shutdown_tx: None,
                    }),
                    sample_rate,
                })
            }
        }
    }

    pub fn sample_rate(&self) -> u32 {
        self.sample_rate
    }

    /// Attach FIM observation to the syscall audit consumer.
    ///
    /// Safe to call after `try_start` (including after the ringbuf consumer is running).
    pub fn set_fim_observer(&self, observer: SyscallFimObserver) {
        let inner = self.inner.lock();
        if let Some(mon) = inner.monitor.as_ref() {
            mon.set_fim_observer(observer);
            info!("FIM observer attached to syscall audit consumer");
        } else {
            warn!("syscall audit monitor absent; FIM bridge not attached");
        }
    }

    /// Register audit + anomaly state for a sandbox at create/prepare time.
    pub fn register_sandbox(&self, sandbox_id: &str, cgroup_id: u64, image: &str, workload: &str) {
        let type_key = sandbox_type_key(image, workload);
        let mut inner = self.inner.lock();
        let Some(mon) = inner.monitor.as_mut() else {
            return;
        };
        if let Err(err) =
            mon.register_sandbox_audit(sandbox_id, cgroup_id, &type_key, true, self.sample_rate)
        {
            warn!(
                sandbox_id,
                cgroup_id,
                type_key = %type_key,
                error = %err,
                "failed to register sandbox for syscall audit"
            );
            return;
        }
        info!(
            sandbox_id,
            cgroup_id,
            type_key = %type_key,
            sample_rate = self.sample_rate,
            "sandbox registered for syscall audit / anomaly baselines"
        );
    }

    /// Tear down audit state when a sandbox is destroyed.
    pub fn unregister_sandbox(&self, sandbox_id: &str, cgroup_id: u64) {
        let mut inner = self.inner.lock();
        let Some(mon) = inner.monitor.as_mut() else {
            return;
        };
        if let Err(err) = mon.unregister_sandbox_audit(sandbox_id, cgroup_id) {
            warn!(
                sandbox_id,
                cgroup_id,
                error = %err,
                "failed to unregister sandbox syscall audit"
            );
        }
    }

    /// Optional: override detector config before sandboxes are registered.
    pub fn set_detector_config(&self, config: DetectorConfig) {
        let mut inner = self.inner.lock();
        if let Some(mon) = inner.monitor.as_mut() {
            mon.set_anomaly_config(config);
        }
    }

    pub fn active(&self) -> bool {
        self.inner.lock().monitor.is_some()
    }
}

impl Drop for SyscallAuditService {
    fn drop(&mut self) {
        let mut inner = self.inner.lock();
        if let Some(tx) = inner.shutdown_tx.take() {
            let _ = tx.send(true);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pico_runtime_hardening::ebpf::syscall::{SYSCALL_OPENAT, SyscallEvent};
    use pico_runtime_hardening::fim::{FileIntegrityChecker, FimMode, O_WRONLY};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn try_start_does_not_panic() {
        let svc = SyscallAuditService::try_start();
        svc.register_sandbox("sb-test", 1, "alpine", "default");
        svc.unregister_sandbox("sb-test", 1);
    }

    #[test]
    fn fim_observer_can_be_attached_and_invoked_on_stub() {
        let svc = SyscallAuditService::try_start();
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_c = Arc::clone(&hits);
        let checker = Arc::new(FileIntegrityChecker::with_defaults());
        checker.register_sandbox("sb", 7, FimMode::Audit, None);

        svc.set_fim_observer(Arc::new(move |sid, ev| {
            hits_c.fetch_add(1, Ordering::Relaxed);
            let _ = checker.observe_syscall_event(sid, ev);
        }));

        // On stub platforms the ringbuf consumer is not running; invoke via monitor API.
        if let Some(mon) = svc.inner.lock().monitor.as_ref() {
            let event = SyscallEvent {
                cgroup_id: 7,
                pid: 1,
                tid: 1,
                uid: 0,
                gid: 0,
                syscall_name: "openat".into(),
                syscall_nr: SYSCALL_OPENAT,
                timestamp_ns: 1,
                arg0: 0,
                arg1: 0,
                arg2: O_WRONLY,
                arg3: 0,
                retval: -1,
                string_arg0: Some("/etc/passwd".into()),
                string_arg1: None,
                is_enter: true,
            };
            mon.observe_fim("sb", &event);
            assert_eq!(hits.load(Ordering::Relaxed), 1);
        }
    }
}

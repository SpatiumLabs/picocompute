//! Idle timeout tracking for host-managed sandboxes.
//!
//! The reaper keeps in-memory deadlines per sandbox and publishes an expiry
//! event when a deadline passes. `HostAgent` subscribes to those events and
//! translates them into sandbox destruction.

use hashbrown::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, Notify, broadcast, watch};
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep_until};

struct ReaperEntry {
    deadline: Instant,
}

/// Tracks idle timers and publishes sandbox ids when their timers expire.
pub struct IdleReaper {
    default_timeout: Duration,
    per_sandbox: Mutex<HashMap<String, ReaperEntry>>,
    notify: Notify,
    expiry_tx: broadcast::Sender<String>,
    shutdown_tx: watch::Sender<bool>,
    sleep_loop: Mutex<Option<JoinHandle<()>>>,
}

impl IdleReaper {
    /// Creates an idle reaper with the default timeout for new timers.
    ///
    /// A background task is spawned immediately and lives until `shutdown` is
    /// called or the process exits.
    #[must_use]
    pub fn new(default_timeout: Duration) -> Arc<Self> {
        let (expiry_tx, _) = broadcast::channel(64);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let reaper = Arc::new(Self {
            default_timeout,
            per_sandbox: Mutex::new(HashMap::new()),
            notify: Notify::new(),
            expiry_tx,
            shutdown_tx,
            sleep_loop: Mutex::new(None),
        });

        let loop_reaper = Arc::clone(&reaper);
        let handle = tokio::spawn(async move {
            loop_reaper.run_loop(shutdown_rx).await;
        });
        if let Ok(mut guard) = reaper.sleep_loop.try_lock() {
            *guard = Some(handle);
        }
        reaper
    }

    /// Returns the default timeout used by `arm` and by sandboxes without an override.
    #[must_use]
    pub fn default_timeout(&self) -> Duration {
        self.default_timeout
    }

    /// Arms or replaces the idle timer for a sandbox.
    pub async fn arm(&self, sandbox_id: &str) {
        self.arm_with_timeout(sandbox_id, self.default_timeout)
            .await;
    }

    /// Arms or replaces the idle timer for a sandbox with a specific timeout.
    pub async fn arm_with_timeout(&self, sandbox_id: &str, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        self.per_sandbox
            .lock()
            .await
            .insert(sandbox_id.to_string(), ReaperEntry { deadline });
        self.notify.notify_one();
    }

    /// Resets a sandbox idle timer to the full timeout.
    pub async fn reset(&self, sandbox_id: &str) {
        self.arm(sandbox_id).await;
    }

    /// Removes a sandbox idle timer.
    pub async fn disarm(&self, sandbox_id: &str) {
        self.per_sandbox.lock().await.remove(sandbox_id);
        self.notify.notify_one();
    }

    /// Subscribes to idle expiry events.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<String> {
        self.expiry_tx.subscribe()
    }

    /// Stops the background reaper loop.
    pub async fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
        self.notify.notify_one();
        if let Some(handle) = self.sleep_loop.lock().await.take() {
            handle.abort();
        }
    }

    async fn run_loop(self: Arc<Self>, mut shutdown_rx: watch::Receiver<bool>) {
        loop {
            if *shutdown_rx.borrow() {
                return;
            }

            let next_deadline = {
                let guard = self.per_sandbox.lock().await;
                guard.values().map(|entry| entry.deadline).min()
            };

            match next_deadline {
                Some(deadline) => {
                    tokio::select! {
                        _ = shutdown_rx.changed() => continue,
                        () = self.notify.notified() => continue,
                        () = sleep_until(deadline) => {
                            self.expire_due().await;
                        }
                    }
                }
                None => {
                    tokio::select! {
                        _ = shutdown_rx.changed() => continue,
                        () = self.notify.notified() => continue,
                    }
                }
            }
        }
    }

    async fn expire_due(&self) {
        let now = Instant::now();
        let expired = {
            let mut guard = self.per_sandbox.lock().await;
            let expired: Vec<String> = guard
                .iter()
                .filter(|(_, entry)| entry.deadline <= now)
                .map(|(sandbox_id, _)| sandbox_id.clone())
                .collect();
            for sandbox_id in &expired {
                guard.remove(sandbox_id);
            }
            expired
        };

        for sandbox_id in expired {
            tracing::info!(sandbox_id = %sandbox_id, "idle reaper firing");
            let _ = self.expiry_tx.send(sandbox_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn arm_and_disarm() {
        let reaper = IdleReaper::new(Duration::from_millis(100));
        reaper.arm("sbx_a").await;
        reaper.disarm("sbx_a").await;
        reaper.shutdown().await;
    }

    #[tokio::test]
    async fn reset_replaces_deadline() {
        let reaper = IdleReaper::new(Duration::from_millis(100));
        reaper.arm("sbx_a").await;
        reaper.reset("sbx_a").await;
        reaper.disarm("sbx_a").await;
        reaper.shutdown().await;
    }

    #[tokio::test]
    async fn expiry_publishes_sandbox_id() {
        let reaper = IdleReaper::new(Duration::from_millis(20));
        let mut rx = reaper.subscribe();
        reaper.arm("sbx_a").await;
        let sandbox_id = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(sandbox_id, "sbx_a");
        reaper.shutdown().await;
    }

    #[tokio::test]
    async fn arm_with_timeout_uses_per_sandbox_timeout() {
        let reaper = IdleReaper::new(Duration::from_secs(10));
        let mut rx = reaper.subscribe();
        reaper
            .arm_with_timeout("sbx_a", Duration::from_millis(20))
            .await;
        let sandbox_id = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(sandbox_id, "sbx_a");
        reaper.shutdown().await;
    }
}

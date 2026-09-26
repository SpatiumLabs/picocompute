//! TCP port proxying from host listeners into sandbox guest services.
//!
//! Each binding owns one host `TcpListener` keyed by `(sandbox_id, port)`.
//! Accepted connections resolve the current guest address or call the wake
//! callback, then copy bytes bidirectionally until either side closes or the
//! endpoint is revoked.

use hashbrown::HashMap;
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

struct ProxyEntry {
    accept_task: JoinHandle<()>,
    cancel: CancellationToken,
    host_port: u16,
}

/// Resolves the guest-side address for a sandbox port.
pub type ResolveAddr = Arc<
    dyn Fn(&str, u16) -> Pin<Box<dyn Future<Output = Option<SocketAddr>> + Send>> + Send + Sync,
>;

/// Wakes a sandbox and resolves the guest-side address once it is ready.
pub type WakeFn = Arc<
    dyn Fn(&str, u16) -> Pin<Box<dyn Future<Output = Option<SocketAddr>> + Send>> + Send + Sync,
>;

/// Connection-limit policy for one proxied port.
#[derive(Debug, Clone, Default)]
pub struct BindOptions {
    /// Cancellation token that terminates the accept loop and active
    /// connections when cancelled.
    pub cancel: Option<CancellationToken>,
    /// Maximum number of concurrent forwarded connections. `None` means no
    /// explicit limit beyond OS resources.
    pub max_connections: Option<usize>,
}

/// Owns TCP listeners that proxy host ports into sandbox guest ports.
pub struct PortProxyManager {
    proxies: Mutex<HashMap<(String, u16), ProxyEntry>>,
    resolve: ResolveAddr,
    wake: WakeFn,
}

impl PortProxyManager {
    /// Creates a port proxy manager with sandbox address resolution callbacks.
    ///
    /// `resolve` is tried first for already-running sandboxes. `wake` is called
    /// when no address is available and may start the sandbox before returning
    /// its guest-side address.
    #[must_use]
    pub fn new(resolve: ResolveAddr, wake: WakeFn) -> Self {
        Self {
            proxies: Mutex::new(HashMap::new()),
            resolve,
            wake,
        }
    }

    /// Binds a host port for a sandbox guest port. Calling this twice for the same pair is a no-op.
    ///
    /// Returns the bound host port. If `host_port` is `0`, an ephemeral port is
    /// chosen by the OS.
    ///
    /// # Errors
    ///
    /// Returns any OS error from binding the TCP listener.
    pub async fn bind(
        self: Arc<Self>,
        sandbox_id: &str,
        host_port: u16,
        guest_port: u16,
        localhost_only: bool,
    ) -> io::Result<u16> {
        self.bind_with_options(
            sandbox_id,
            host_port,
            guest_port,
            localhost_only,
            BindOptions::default(),
        )
        .await
    }

    /// Binds a host port with revocation and concurrency controls.
    ///
    /// # Errors
    ///
    /// Returns any OS error from binding the TCP listener.
    pub async fn bind_with_options(
        self: Arc<Self>,
        sandbox_id: &str,
        host_port: u16,
        guest_port: u16,
        localhost_only: bool,
        options: BindOptions,
    ) -> io::Result<u16> {
        let mut guard = self.proxies.lock().await;

        // If the caller requested a concrete host port and we already proxy it
        // for this sandbox, return the existing binding.
        if host_port != 0
            && let Some(entry) = guard.get(&(sandbox_id.to_string(), host_port))
        {
            return Ok(entry.host_port);
        }

        let bind_ip = if localhost_only {
            Ipv4Addr::LOCALHOST
        } else {
            Ipv4Addr::UNSPECIFIED
        };
        let listener = TcpListener::bind((bind_ip, host_port)).await?;
        let actual_host_port = listener.local_addr()?.port();

        let cancel = options.cancel.unwrap_or_default();
        let sem = options
            .max_connections
            .map(|limit| Arc::new(Semaphore::new(limit)));

        let sid = sandbox_id.to_string();
        let manager = Arc::downgrade(&self);
        let accept_cancel = cancel.clone();
        let accept_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = accept_cancel.cancelled() => {
                        break;
                    }
                    res = listener.accept() => match res {
                        Ok((downstream, _)) => {
                            let Some(manager) = manager.upgrade() else {
                                break;
                            };
                            let sid = sid.clone();
                            let conn_cancel = accept_cancel.child_token();
                            let sem = sem.clone();
                            tokio::spawn(async move {
                                let _permit = if let Some(s) = sem {
                                    // The semaphore is never closed by this component.
                                    Some(s.acquire_owned().await.expect("proxy semaphore closed"))
                                } else {
                                    None
                                };
                                if let Err(err) = manager
                                    .handle_connection(&sid, guest_port, downstream, conn_cancel)
                                    .await
                                {
                                    tracing::warn!(
                                        sandbox_id = %sid,
                                        guest_port,
                                        error = %err,
                                        "proxy connection failed"
                                    );
                                }
                            });
                        }
                        Err(err) => {
                            tracing::warn!(host_port = actual_host_port, error = %err, "proxy accept failed");
                            if accept_cancel.is_cancelled() {
                                break;
                            }
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
            }

            // Remove the binding once the accept loop exits so that
            // `bound_ports` and callers see the endpoint as released.
            if let Some(manager) = manager.upgrade() {
                manager
                    .proxies
                    .lock()
                    .await
                    .remove(&(sid.clone(), actual_host_port));
            }
        });

        guard.insert(
            (sandbox_id.to_string(), actual_host_port),
            ProxyEntry {
                accept_task,
                cancel,
                host_port: actual_host_port,
            },
        );
        Ok(actual_host_port)
    }

    /// Unbinds a single sandbox host port. Missing bindings are ignored.
    pub async fn unbind(&self, sandbox_id: &str, host_port: u16) {
        let mut guard = self.proxies.lock().await;
        if let Some(entry) = guard.remove(&(sandbox_id.to_string(), host_port)) {
            entry.cancel.cancel();
            entry.accept_task.abort();
        }
    }

    /// Unbinds every port for one sandbox. Missing bindings are ignored.
    pub async fn unbind_all(&self, sandbox_id: &str) {
        let mut guard = self.proxies.lock().await;
        let keys: Vec<(String, u16)> = guard
            .keys()
            .filter(|(sid, _)| sid == sandbox_id)
            .cloned()
            .collect();
        for key in keys {
            if let Some(entry) = guard.remove(&key) {
                entry.cancel.cancel();
                entry.accept_task.abort();
            }
        }
    }

    /// Returns the currently bound host ports for one sandbox.
    ///
    /// The result is sorted to make tests and diagnostics stable.
    #[must_use]
    pub async fn bound_ports(&self, sandbox_id: &str) -> Vec<u16> {
        let guard = self.proxies.lock().await;
        let mut ports: Vec<u16> = guard
            .keys()
            .filter(|(sid, _)| sid == sandbox_id)
            .map(|(_, port)| *port)
            .collect();
        ports.sort_unstable();
        ports
    }

    async fn handle_connection(
        &self,
        sandbox_id: &str,
        guest_port: u16,
        mut downstream: TcpStream,
        cancel: CancellationToken,
    ) -> io::Result<()> {
        let upstream_addr = match (self.resolve)(sandbox_id, guest_port).await {
            Some(addr) => addr,
            None => match (self.wake)(sandbox_id, guest_port).await {
                Some(addr) => addr,
                // Fail visibly instead of silently dropping the connection:
                // reset it (linger-0 close) so the client gets an immediate
                // refused connection rather than a hanging socket, and surface
                // the diagnosis in the log for operators.
                None => {
                    tracing::warn!(
                        sandbox_id,
                        guest_port,
                        "refusing inbound connection: no port target (GetPortTarget miss or generation mismatch)"
                    );
                    // RST the connection: a lingering close would hang or read
                    // as a timeout on the client side.
                    let _ = downstream.set_zero_linger();
                    return Err(io::Error::other(
                        "port target unavailable (GetPortTarget miss or generation mismatch)",
                    ));
                }
            },
        };
        let mut upstream = TcpStream::connect(upstream_addr).await?;
        tokio::select! {
            biased;
            _ = cancel.cancelled() => Ok(()),
            result = copy_bidirectional(&mut downstream, &mut upstream) => {
                result.map(|_| ())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener as TokioTcpListener;
    use tokio_util::sync::CancellationToken;

    use super::*;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
    }

    #[tokio::test]
    async fn bind_and_unbind() {
        let probe = TokioTcpListener::bind(addr(0)).await.unwrap();
        let free_port = probe.local_addr().unwrap().port();
        drop(probe);

        let resolve: ResolveAddr = Arc::new(|_, port| Box::pin(async move { Some(addr(port)) }));
        let wake: WakeFn = Arc::new(|_, port| Box::pin(async move { Some(addr(port)) }));
        let manager = Arc::new(PortProxyManager::new(resolve, wake));

        let bound = Arc::clone(&manager)
            .bind("sbx_a", free_port, free_port, false)
            .await
            .unwrap();
        assert_eq!(bound, free_port);
        assert_eq!(manager.bound_ports("sbx_a").await, vec![free_port]);

        let rebound = Arc::clone(&manager)
            .bind("sbx_a", free_port, free_port, false)
            .await
            .unwrap();
        assert_eq!(rebound, free_port);
        assert_eq!(manager.bound_ports("sbx_a").await.len(), 1);

        manager.unbind("sbx_a", free_port).await;
        assert!(manager.bound_ports("sbx_a").await.is_empty());
    }

    #[tokio::test]
    async fn bind_allocates_ephemeral_port_when_zero() {
        let resolve: ResolveAddr = Arc::new(|_, port| Box::pin(async move { Some(addr(port)) }));
        let wake: WakeFn = Arc::new(|_, port| Box::pin(async move { Some(addr(port)) }));
        let manager = Arc::new(PortProxyManager::new(resolve, wake));

        let bound = Arc::clone(&manager)
            .bind("sbx_a", 0, 3000, true)
            .await
            .unwrap();
        assert_ne!(bound, 0);
        assert_eq!(manager.bound_ports("sbx_a").await, vec![bound]);

        manager.unbind("sbx_a", bound).await;
    }

    #[tokio::test]
    async fn unbind_all_removes_only_specific_sandbox() {
        let probe = TokioTcpListener::bind(addr(0)).await.unwrap();
        let p1 = probe.local_addr().unwrap().port();
        drop(probe);
        let probe = TokioTcpListener::bind(addr(0)).await.unwrap();
        let p2 = probe.local_addr().unwrap().port();
        drop(probe);

        let resolve: ResolveAddr = Arc::new(|_, port| Box::pin(async move { Some(addr(port)) }));
        let wake: WakeFn = Arc::new(|_, port| Box::pin(async move { Some(addr(port)) }));
        let manager = Arc::new(PortProxyManager::new(resolve, wake));

        Arc::clone(&manager)
            .bind("sbx_a", p1, p1, false)
            .await
            .unwrap();
        Arc::clone(&manager)
            .bind("sbx_b", p2, p2, false)
            .await
            .unwrap();

        manager.unbind_all("sbx_a").await;
        assert!(manager.bound_ports("sbx_a").await.is_empty());
        assert_eq!(manager.bound_ports("sbx_b").await, vec![p2]);
    }

    #[tokio::test]
    async fn proxy_bytes_between_two_listeners() {
        let server = TokioTcpListener::bind(addr(0)).await.unwrap();
        let server_port = server.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = server.accept().await {
                let mut buf = [0u8; 4];
                sock.read_exact(&mut buf).await.unwrap();
                sock.write_all(b"pong").await.unwrap();
            }
        });

        let probe = TokioTcpListener::bind(addr(0)).await.unwrap();
        let proxy_port = probe.local_addr().unwrap().port();
        drop(probe);

        let resolve: ResolveAddr =
            Arc::new(move |_, _| Box::pin(async move { Some(addr(server_port)) }));
        let wake: WakeFn = Arc::new(|_, port| Box::pin(async move { Some(addr(port)) }));
        let manager = Arc::new(PortProxyManager::new(resolve, wake));
        Arc::clone(&manager)
            .bind("sbx_a", proxy_port, 80, false)
            .await
            .unwrap();

        let mut client = TcpStream::connect(addr(proxy_port)).await.unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf, b"pong");
    }

    #[tokio::test]
    async fn cancellation_token_terminates_accept_loop() {
        let resolve: ResolveAddr = Arc::new(|_, port| Box::pin(async move { Some(addr(port)) }));
        let wake: WakeFn = Arc::new(|_, port| Box::pin(async move { Some(addr(port)) }));
        let manager = Arc::new(PortProxyManager::new(resolve, wake));
        let cancel = CancellationToken::new();

        let bound = Arc::clone(&manager)
            .bind_with_options(
                "sbx_a",
                0,
                3000,
                true,
                BindOptions {
                    cancel: Some(cancel.clone()),
                    max_connections: None,
                },
            )
            .await
            .unwrap();

        assert!(!manager.bound_ports("sbx_a").await.is_empty());
        cancel.cancel();
        // Give the accept task a moment to observe cancellation and remove itself.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(manager.bound_ports("sbx_a").await.is_empty());

        // The port should be free to bind again.
        let reuse = TokioTcpListener::bind(addr(bound)).await;
        assert!(reuse.is_ok());
    }

    #[tokio::test]
    async fn max_connections_limits_concurrent_connections() {
        let listener = TokioTcpListener::bind(addr(0)).await.unwrap();
        let server_port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            // Accept one connection and hold it open.
            if let Ok((_, _)) = listener.accept().await {}
        });

        let resolve: ResolveAddr =
            Arc::new(move |_, _| Box::pin(async move { Some(addr(server_port)) }));
        let wake: WakeFn = Arc::new(|_, port| Box::pin(async move { Some(addr(port)) }));
        let manager = Arc::new(PortProxyManager::new(resolve, wake));
        let cancel = CancellationToken::new();

        let bound = Arc::clone(&manager)
            .bind_with_options(
                "sbx_a",
                0,
                3000,
                true,
                BindOptions {
                    cancel: Some(cancel.clone()),
                    max_connections: Some(1),
                },
            )
            .await
            .unwrap();

        // First client connects and is proxied to the held-open server.
        let _client1 = TcpStream::connect(addr(bound)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Second client can connect to the local listener but the proxy task
        // cannot acquire a second permit, so it will block until the first
        // connection is released. We verify this by attempting to read from the
        // second client with a short timeout -- no data will be forwarded.
        let mut client2 = TcpStream::connect(addr(bound)).await.unwrap();
        let mut buf = [0u8; 1];
        let read_result =
            tokio::time::timeout(Duration::from_millis(150), client2.read(&mut buf)).await;
        assert!(read_result.is_err());

        cancel.cancel();
    }

    #[tokio::test]
    async fn unresolved_target_refuses_connection_with_reset() {
        // Fail-closed proxy: when neither resolve nor wake produces a target
        // (GetPortTarget miss / generation mismatch), the accepted connection
        // must be reset promptly rather than accepted and silently dropped.
        let resolve: ResolveAddr = Arc::new(|_, _| Box::pin(async move { None }));
        let wake: WakeFn = Arc::new(|_, _| Box::pin(async move { None }));
        let manager = Arc::new(PortProxyManager::new(resolve, wake));

        let probe = TokioTcpListener::bind(addr(0)).await.unwrap();
        let proxy_port = probe.local_addr().unwrap().port();
        drop(probe);
        Arc::clone(&manager)
            .bind("sbx_a", proxy_port, 22, true)
            .await
            .unwrap();

        let mut client = TcpStream::connect(addr(proxy_port)).await.unwrap();
        let mut buf = [0u8; 1];
        let read_result = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf)).await;
        // The connection must be closed (reset/EOF), never held open.
        assert!(
            read_result.is_ok(),
            "unresolvable target must not hang the client"
        );
        manager.unbind("sbx_a", proxy_port).await;
    }

    #[tokio::test]
    async fn generation_mismatch_resolve_fail_closed() {
        // Simulate a stale cache: resolve returns None (generation mismatch /
        // invalidated route). The proxy must still RST rather than hang.
        let resolve: ResolveAddr = Arc::new(|_, _| Box::pin(async move { None }));
        let wake: WakeFn = Arc::new(|_, _| Box::pin(async move { None }));
        let manager = Arc::new(PortProxyManager::new(resolve, wake));
        let bound = Arc::clone(&manager)
            .bind("sbx_gen", 0, 8080, true)
            .await
            .unwrap();

        let mut client = TcpStream::connect(addr(bound)).await.unwrap();
        let mut buf = [0u8; 1];
        let read_result = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf)).await;
        assert!(read_result.is_ok(), "stale generation must fail closed");
        manager.unbind("sbx_gen", bound).await;
    }
}

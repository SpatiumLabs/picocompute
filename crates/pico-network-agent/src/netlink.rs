//! Platform abstraction for netlink operations.
//!
//! On Linux, this re-exports the `rtnetlink` Handle type.
//! On non-Linux platforms, it provides a stub Handle that all operations panic.

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(not(target_os = "linux"))]
pub use stub::*;

#[cfg(target_os = "linux")]
mod linux {
    use std::future::Future;

    pub use rtnetlink::Error as NetlinkError;
    pub use rtnetlink::Handle;
    pub use rtnetlink::LinkMessageBuilder;
    pub use rtnetlink::LinkUnspec;
    pub use rtnetlink::LinkVeth;
    pub use rtnetlink::packet_route as packet;
    pub use tun;

    /// Opens a netlink connection.
    ///
    /// Returns the same 2-tuple as the non-Linux stub. rtnetlink 0.23 also
    /// yields an unsolicited-message receiver; callers do not use it.
    pub fn new_connection() -> std::io::Result<(impl Future + Send + 'static, Handle)> {
        let (conn, handle, _) = rtnetlink::new_connection()?;
        Ok((conn, handle))
    }
}

#[cfg(not(target_os = "linux"))]
mod stub {
    use std::future::Future;
    use std::pin::Pin;

    /// Stub Handle for non-Linux platforms.
    /// All methods panic with "netlink not available on this platform".
    #[derive(Clone)]
    pub struct Handle;

    impl Handle {
        pub fn link(&self) -> StubLink {
            StubLink
        }
        pub fn address(&self) -> StubAddress {
            StubAddress
        }
        pub fn route(&self) -> StubRoute {
            StubRoute
        }
    }

    pub struct StubLink;
    impl StubLink {
        pub fn get(&self) -> StubLinkGet {
            StubLinkGet
        }
        pub fn add(&self, _msg: StubLinkMessage) -> StubLinkAdd {
            StubLinkAdd
        }
        pub fn del(&self, _index: u32) -> StubLinkDel {
            StubLinkDel
        }
        pub fn set(&self, _index: u32) -> StubLinkSet {
            StubLinkSet
        }
    }

    pub struct StubLinkGet;
    impl StubLinkGet {
        pub fn match_name(self, _name: String) -> Self {
            self
        }
        pub fn execute(self) -> StubLinkStream {
            StubLinkStream
        }
    }

    pub struct StubLinkAdd;
    impl StubLinkAdd {
        pub fn execute(self) -> StubNetlinkFuture {
            StubNetlinkFuture
        }
    }

    pub struct StubLinkDel;
    impl StubLinkDel {
        pub fn execute(self) -> StubNetlinkFuture {
            StubNetlinkFuture
        }
    }

    pub struct StubLinkSet;
    impl StubLinkSet {
        pub fn up(self) -> Self {
            self
        }
        pub fn setns(self, _fd: i32) -> StubLinkSetNs {
            StubLinkSetNs
        }
        pub fn execute(self) -> StubNetlinkFuture {
            StubNetlinkFuture
        }
    }

    pub struct StubLinkSetNs;
    impl StubLinkSetNs {
        pub fn execute(self) -> StubNetlinkFuture {
            StubNetlinkFuture
        }
    }

    pub struct StubAddress;
    impl StubAddress {
        pub fn add(&self, _index: u32, _addr: std::net::IpAddr, _prefix_len: u8) -> StubAddressAdd {
            StubAddressAdd
        }
    }

    pub struct StubAddressAdd;
    impl StubAddressAdd {
        pub fn execute(self) -> StubNetlinkFuture {
            StubNetlinkFuture
        }
    }

    pub struct StubRoute;
    impl StubRoute {
        pub fn add(&self) -> StubRouteAdd {
            StubRouteAdd
        }
    }

    pub struct StubRouteAdd;
    impl StubRouteAdd {
        pub fn execute(self) -> StubNetlinkFuture {
            StubNetlinkFuture
        }
    }

    pub struct StubLinkStream;
    impl StubLinkStream {
        pub async fn next(&mut self) -> Option<StubLinkMessage> {
            None
        }
    }

    pub struct StubLinkMessage {
        pub header: StubLinkHeader,
    }

    pub struct StubLinkHeader {
        pub index: u32,
    }

    pub struct StubNetlinkFuture;

    impl Future for StubNetlinkFuture {
        type Output = Result<(), std::io::Error>;

        fn poll(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Self::Output> {
            std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "netlink operations are only available on Linux",
            )))
        }
    }

    /// Creates a stub connection that returns an error when used.
    pub fn new_connection() -> Result<(StubConnection, Handle), std::io::Error> {
        Ok((StubConnection, Handle))
    }

    pub struct StubConnection;
    impl Future for StubConnection {
        type Output = Result<(), ()>;
        fn poll(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Self::Output> {
            std::task::Poll::Ready(Ok(()))
        }
    }
}

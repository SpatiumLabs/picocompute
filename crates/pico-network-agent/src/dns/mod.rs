//! DNS proxy module: policy, server, cache, resolver, metrics, and audit.
//!
//! The DNS proxy enforces tenant-level allow/deny domain policies on
//! sandbox-originated DNS queries. Queries are redirected to the proxy
//! via nftables prerouting rules installed by [`crate::dns_attachment`].

pub mod cache;
mod metrics;
pub mod policy;
pub mod resolver;
pub mod server;

pub use policy::{DnsAction, DnsDecision, DnsPatternType, DnsPolicy, DnsProxyConfig, DnsRule};
pub use server::{DnsAuditContext, DnsAuditSink, DnsProxy, NoopDnsAuditSink};

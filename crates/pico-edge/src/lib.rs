//! PicoCompute Edge Gateway — Pingora-based HTTP/WebSocket proxy with lease validation.
//!
//! Sits in front of host-agent port-forward TCP endpoints and provides:
//!
//! - TLS termination
//! - Access lease validation (reuses [`LeaseManager`] from `pico-core`)
//! - Host-header–based routing to sandbox TCP backends
//! - WebSocket upgrade support with bidirectional streaming
//! - Graceful reload via Pingora
//! - Per-endpoint rate limits and connection limits
//! - Audit event emission for every proxied connection
//!
//! ## Architecture
//!
//! ```text
//! Client ─── TLS ─── pico-edge ─── TCP ─── host-agent:port-forward
//!                          │
//!                          ├── LeaseManager (lease validation)
//!                          └── AuditEventSink (audit trail)
//! ```

pub mod config;
pub mod proxy;
pub mod routing;

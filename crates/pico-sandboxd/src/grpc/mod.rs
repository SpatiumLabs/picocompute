//! gRPC control plane over Unix domain sockets.

mod auth;
mod convert;
/// UDS bind and serve entrypoints used by the sandboxd binary.
pub mod server;
mod service;

pub use auth::AuthInterceptor;
pub use service::SandboxdService;

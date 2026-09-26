//! Generated protobuf and gRPC bindings for host-agent to sandboxd control.
//!
//! # Schema
//!
//! - [`v1`] (`pico.sandboxd.v1`) — sole `Sandboxd` service (Interface 1)
//!
//! # Status mapping
//!
//! [`status`] maps outcome wire enums and supervisor error classes to
//! [`tonic::Code`] without depending on the `pico-sandboxd` crate.

#![expect(
    clippy::clone_on_ref_ptr,
    reason = "tonic-generated client clones Arc inner; upstream template, not hand-written code"
)]

pub mod status;

/// Generated types and `Sandboxd` client/server for `pico.sandboxd.v1`.
pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/pico.sandboxd.v1.rs"));
}

pub use status::{
    METADATA_TOKEN_KEY, SupervisorErrorClass, outcome_reason_to_code, outcome_status_to_code,
    outcome_to_code, status_from_outcome_fields,
};

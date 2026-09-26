//! Generated protobuf and gRPC bindings for the PicoCompute host-guest
//! control protocol.
//!
//! # Schema packages
//!
//! - [`pico::guest::bootstrap::v1`] — pre-negotiation handshake
//!   and mutual authentication.
//! - [`pico::guest::v1`] — operational RPCs (exec, file transfer,
//!   mount, stats, health, quiesce, resume, shutdown).

#![expect(
    clippy::large_enum_variant,
    reason = "protobuf-generated enums are intentionally sized for the wire format"
)]
#![expect(
    clippy::clone_on_ref_ptr,
    reason = "tonic-generated client clones Arc inner; upstream template, not hand-written code"
)]

pub mod exec;
pub mod framed;
pub mod handshake;
pub mod session;

pub mod pico {
    pub mod guest {
        pub mod bootstrap {
            pub mod v1 {
                include!(concat!(env!("OUT_DIR"), "/pico.guest.bootstrap.v1.rs"));
            }
        }
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/pico.guest.v1.rs"));
        }
    }
}

/// Convenience re-export for bootstrap types (pico::guest::bootstrap::v1).
pub use pico::guest::bootstrap::v1 as bootstrap_v1;

/// Convenience re-export for operational types (pico::guest::v1).
pub use pico::guest::v1 as operational_v1;

// Primary API surface. Consumers import these from the crate root; do not
// reach into `session::` / `handshake::` / `framed::` module paths from
// other crates.
pub use framed::{FramedConnection, TransportStream};
pub use handshake::{
    HandshakeConfig, HandshakeError, HandshakeOutcome, compute_guest_proof,
    perform_handshake_exchange,
};
pub use session::{
    DEFAULT_MAX_FILE_BYTES, DEFAULT_MAX_STDERR_BYTES, DEFAULT_MAX_STDOUT_BYTES, ExecResult,
    GetFileResult, GuestSession, InjectSecretsResult, MAX_FRAME_PAYLOAD_BYTES, SessionError,
};

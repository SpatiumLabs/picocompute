//! Guest-agent session ownership for sandboxd.
//!
//! sandboxd is the sole owner of framed guest sessions: bootstrap handshake,
//! exec streaming demux, file I/O, and cancel.

mod connection;
mod handshake;

pub use connection::{
    ExecResult, ExecStreamEvent, GetFileResult, GuestClientError, GuestConnection,
};
pub use handshake::{HandshakeConfig, HandshakeError, HandshakeOutcome};

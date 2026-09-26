//! Host-side sandbox workspace directories and path validation.
//!
//! The implementation lives in `pico-core` so both host-agent and
//! sandboxd share one workspace management path.

pub use pico_core::workspace::*;

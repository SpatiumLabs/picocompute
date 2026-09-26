//! Runtime secrets broker integration.
//!
//! Provides the shared types, errors, and broker trait used by the
//! host-agent to fetch just-in-time credentials and by the guest-agent
//! to receive them.

pub mod broker;
pub mod error;
#[cfg(feature = "secrets-http")]
pub mod http;
pub mod mock;
pub mod types;

pub use broker::SecretsBroker;
pub use error::SecretsBrokerError;
pub use types::{CredentialBundle, CredentialRef, CredentialRequest, CredentialValue};

#[cfg(feature = "secrets-http")]
pub use http::{HttpBrokerConfig, HttpSecretsBroker};

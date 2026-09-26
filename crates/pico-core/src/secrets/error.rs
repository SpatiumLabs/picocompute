//! Errors returned by secrets broker operations.

use thiserror::Error;

/// Errors that can occur when fetching or validating credentials.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SecretsBrokerError {
    /// The lease or policy decision does not authorize credential access.
    #[error("credential access denied: {0}")]
    Denied(String),

    /// The broker is unreachable or returned an unavailable response.
    #[error("broker unavailable: {0}")]
    Unavailable(String),

    /// The broker request failed at the transport or protocol layer.
    #[error("broker request failed: {0}")]
    RequestFailed(String),

    /// The broker response was malformed or missing required fields.
    #[error("invalid broker response: {0}")]
    InvalidResponse(String),

    /// The requested credential type is not recognized by the broker.
    #[error("unknown credential type: {0}")]
    UnknownCredentialType(String),
}

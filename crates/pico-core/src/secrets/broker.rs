//! Abstract secrets broker interface.

use async_trait::async_trait;

use crate::secrets::{CredentialBundle, CredentialRequest, SecretsBrokerError};

/// A pluggable backend that fetches short-lived runtime credentials.
#[async_trait]
pub trait SecretsBroker: Send + Sync {
    /// Fetch credentials for the given request context.
    ///
    /// The caller is responsible for validating the access lease or policy
    /// decision before invoking the broker. Implementations must never log
    /// secret values.
    async fn fetch_credentials(
        &self,
        request: &CredentialRequest,
    ) -> Result<CredentialBundle, SecretsBrokerError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    // Compile-time check that the trait is object-safe.
    #[test]
    fn trait_is_object_safe() {
        let _: Option<Box<dyn SecretsBroker>> = None;
    }
}

//! Token metadata + SO_PEERCRED interceptors for the sandboxd gRPC surface.

use std::sync::Arc;

use pico_sandboxd_proto::{METADATA_TOKEN_KEY, SupervisorErrorClass};
use subtle::ConstantTimeEq;
use tonic::Status;
use tonic::service::Interceptor;
use tonic::transport::server::UdsConnectInfo;

/// Shared auth state applied on every RPC.
#[derive(Clone)]
pub struct AuthInterceptor {
    token: Arc<str>,
    allowed_peer_uids: Arc<[u32]>,
}

impl AuthInterceptor {
    /// Builds an interceptor that requires a matching metadata token and, when
    /// `allowed_peer_uids` is non-empty, a peer UID on that allowlist.
    #[must_use]
    pub fn new(token: impl Into<String>, allowed_peer_uids: Vec<u32>) -> Self {
        Self {
            token: Arc::from(token.into()),
            allowed_peer_uids: Arc::from(allowed_peer_uids),
        }
    }
}

impl Interceptor for AuthInterceptor {
    fn call(&mut self, request: tonic::Request<()>) -> Result<tonic::Request<()>, Status> {
        authorize_token(request.metadata(), self.token.as_ref())?;
        authorize_peercred(request.extensions(), &self.allowed_peer_uids)?;
        Ok(request)
    }
}

fn authorize_token(metadata: &tonic::metadata::MetadataMap, expected: &str) -> Result<(), Status> {
    let presented = metadata
        .get(METADATA_TOKEN_KEY)
        .and_then(|value| value.to_str().ok());
    let authorized = presented
        .map(|value| bool::from(value.as_bytes().ct_eq(expected.as_bytes())))
        .unwrap_or(false);
    if authorized {
        Ok(())
    } else {
        Err(SupervisorErrorClass::Unauthenticated.status("missing or invalid sandboxd auth token"))
    }
}

fn authorize_peercred(
    extensions: &tonic::Extensions,
    allowed_peer_uids: &[u32],
) -> Result<(), Status> {
    if allowed_peer_uids.is_empty() {
        return Ok(());
    }

    let Some(info) = extensions.get::<UdsConnectInfo>() else {
        return Err(SupervisorErrorClass::Unauthenticated.status("missing unix peer credentials"));
    };
    let Some(cred) = info.peer_cred.as_ref() else {
        return Err(
            SupervisorErrorClass::Unauthenticated.status("unavailable unix peer credentials")
        );
    };
    let uid = cred.uid();
    if allowed_peer_uids.contains(&uid) {
        Ok(())
    } else {
        Err(SupervisorErrorClass::PermissionDenied.status(format!("peer uid {uid} is not allowed")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::metadata::MetadataValue;

    #[test]
    fn rejects_missing_token() {
        let mut interceptor = AuthInterceptor::new("secret", Vec::new());
        let request = tonic::Request::new(());
        let err = interceptor.call(request).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn rejects_wrong_token() {
        let mut interceptor = AuthInterceptor::new("secret", Vec::new());
        let mut request = tonic::Request::new(());
        request
            .metadata_mut()
            .insert(METADATA_TOKEN_KEY, MetadataValue::from_static("wrong"));
        let err = interceptor.call(request).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn accepts_matching_token_without_uid_allowlist() {
        let mut interceptor = AuthInterceptor::new("secret", Vec::new());
        let mut request = tonic::Request::new(());
        request
            .metadata_mut()
            .insert(METADATA_TOKEN_KEY, MetadataValue::from_static("secret"));
        assert!(interceptor.call(request).is_ok());
    }
}

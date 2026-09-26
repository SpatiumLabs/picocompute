//! Upstream DNS resolution via hickory-resolver with answer filtering.
//!
//! Resolves queries using the host's system resolver configuration
//! (`/etc/resolv.conf`) and filters returned addresses against the
//! denied platform/internal CIDR list before returning them.

use std::net::IpAddr;
use std::time::Duration;

use hickory_resolver::TokioResolver;
use hickory_resolver::config::ResolverOpts;
use tracing::debug;

use super::policy::{DENIED_ANSWER_CIDRS, is_denied_ipv4};

/// Error returned when upstream resolution fails or all answers are denied.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("upstream resolution failed: {0}")]
    Upstream(String),
    #[error("all resolved addresses were denied by policy")]
    AllDenied,
}

/// Result with a set of filtered addresses and the upstream TTL.
pub struct ResolvedAnswer {
    pub addresses: Vec<IpAddr>,
    pub min_ttl_secs: u32,
}

/// Async DNS resolver wrapping hickory-resolver with answer filtering.
pub struct DnsResolver {
    inner: TokioResolver,
}

impl DnsResolver {
    /// Create a resolver using the host's system configuration with sensible timeouts.
    pub fn from_system_config() -> Result<Self, String> {
        let res = TokioResolver::builder_tokio()
            .and_then(|mut b| {
                *b.options_mut() = default_resolver_opts();
                b.build()
            })
            .map_err(|e| format!("failed to build system resolver: {e}"))?;
        Ok(Self { inner: res })
    }

    /// Create a resolver with default options (no system config).
    #[must_use]
    pub fn from_fallback() -> Self {
        let res = TokioResolver::builder_tokio()
            .and_then(|mut b| {
                *b.options_mut() = default_resolver_opts();
                b.build()
            })
            .expect("TokioResolver should build with default options");
        Self { inner: res }
    }

    /// Resolve a hostname to a filtered set of IPv4 addresses.
    ///
    /// Performs a lookup and strips any address that falls inside
    /// a denied platform or internal CIDR. If all addresses are
    /// denied, returns `ResolveError::AllDenied`.
    pub async fn resolve_a(&self, qname: &str) -> Result<ResolvedAnswer, ResolveError> {
        let lookup = self
            .inner
            .lookup_ip(qname)
            .await
            .map_err(|e| ResolveError::Upstream(e.to_string()))?;

        let mut min_ttl_secs = u32::MAX;
        let addresses: Vec<IpAddr> = lookup
            .iter()
            .filter(|addr| match addr {
                IpAddr::V4(v4) => !is_denied_ipv4(*v4, DENIED_ANSWER_CIDRS),
                IpAddr::V6(_) => false, // IPv6 blocked
            })
            .collect();

        // Compute the minimum TTL from the resolved records
        for record in lookup.as_lookup().answers() {
            min_ttl_secs = min_ttl_secs.min(record.ttl);
        }

        if addresses.is_empty() {
            debug!(qname, "all resolved addresses denied");
            return Err(ResolveError::AllDenied);
        }

        if min_ttl_secs == u32::MAX {
            min_ttl_secs = 60; // fallback if no records somehow
        }

        Ok(ResolvedAnswer {
            addresses,
            min_ttl_secs,
        })
    }
}

/// Check whether a query name matches a platform-internal suffix.
pub fn is_platform_internal_domain(qname: &str) -> bool {
    super::policy::DEFAULT_DENY_SUFFIXES.iter().any(|suffix| {
        if !qname.ends_with(suffix) {
            return false;
        }
        if suffix.starts_with('.') {
            return true;
        }
        qname.len() == suffix.len() || qname.as_bytes()[qname.len() - suffix.len() - 1] == b'.'
    })
}

/// Build resolver options with sensible timeouts.
pub fn default_resolver_opts() -> ResolverOpts {
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(5);
    opts.cache_size = 0;
    opts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_internal_domains_are_detected() {
        assert!(is_platform_internal_domain("metadata.google.internal"));
        assert!(is_platform_internal_domain("host.internal"));
        assert!(is_platform_internal_domain("foo.local"));
        assert!(is_platform_internal_domain("localhost"));
    }

    #[test]
    fn public_domains_are_not_internal() {
        assert!(!is_platform_internal_domain("example.com"));
        assert!(!is_platform_internal_domain("google.com"));
    }

    #[test]
    fn internal_suffix_matches_subdomains() {
        assert!(is_platform_internal_domain("api.metadata.google.internal"));
    }
}

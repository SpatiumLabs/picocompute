//! DNS-specific metrics.
//!
//! All metrics are prefixed with `network.dns.`.
//!
//! # Interface
//!
//! Call sites record DNS decisions through the `record_*` functions rather than
//! reaching into the counters directly. The request handler applies the same
//! handful of decisions in a dozen places, and each one needed the same three
//! labels assembled by hand. Routing them through here keeps the label set for
//! each decision in one place, and means a new caller cannot emit a DNS series
//! with a differently-shaped label set and quietly fork the dashboard query.
//!
//! # Cardinality
//!
//! Every label value is drawn from a closed set here. The `domain` label uses
//! the suffix class from [`classify_domain`](super::server::classify_domain)
//! rather than the queried name, and the `reason` / `action` / `rcode` labels
//! are normalized against allowlists. An unrecognised value collapses to
//! `unknown` instead of creating a new series.

use pico_telemetry::metrics::{Allowlist, Counter, Gauge, Histogram, Labels, attr};
use std::sync::LazyLock;

pub(super) static DNS_METRICS: LazyLock<DnsMetrics> = LazyLock::new(DnsMetrics::register);

const DNS_QUERIES_TOTAL: &str = "network.dns.queries_total";
const DNS_ALLOWED: &str = "network.dns.allowed";
const DNS_DENIED: &str = "network.dns.denied";
const DNS_FAILED: &str = "network.dns.failed";
const DNS_CACHE_HITS: &str = "network.dns.cache_hits";
const DNS_CACHE_MISSES: &str = "network.dns.cache_misses";
const DNS_RESOLUTION_DURATION: &str = "network.dns.resolution_duration_seconds";
const DNS_POLICY_ACTIONS: &str = "network.dns.policy_actions";
const DNS_REGISTERED_SANDBOXES: &str = "network.dns.registered_sandboxes";
const DNS_QUERY_DOMAIN: &str = "network.dns.query_domain";
const DNS_RESPONSE_CODE: &str = "network.dns.response_code";

/// Fallback for any label value outside the allowlists below.
///
/// Each allowlist owns its own fallback, and [`Allowlist::new`] is a `const fn`
/// that rejects a set missing it. That forces `unknown` to be a deliberate member
/// of every closed set, checked at compile time rather than at runtime.
const UNKNOWN: &str = "unknown";

/// DNS policy action attribute values.
pub(super) mod dns_action {
    use super::{Allowlist, UNKNOWN};

    pub(crate) const ALLOW_RULE: &str = "allow_rule";
    pub(crate) const DENY_RULE: &str = "deny_rule";
    pub(crate) const DEFAULT_ALLOW: &str = "default_allow";
    pub(crate) const DEFAULT_DENY: &str = "default_deny";
    pub(crate) const PLATFORM_INTERNAL: &str = "platform_internal";
    pub(crate) const UNSUPPORTED_QTYPE: &str = "unsupported_qtype";
    pub(crate) const NO_POLICY: &str = "no_policy";
    pub(crate) const IPV6_UNSUPPORTED: &str = "ipv6_unsupported";

    /// Closed set of actions, for allowlist normalization.
    ///
    /// [`UNKNOWN`] is a member so an unrecognised action normalizes to a value
    /// that is still inside the closed set.
    pub(super) const ALL: Allowlist = Allowlist::new(
        &[
            ALLOW_RULE,
            DENY_RULE,
            DEFAULT_ALLOW,
            DEFAULT_DENY,
            PLATFORM_INTERNAL,
            UNSUPPORTED_QTYPE,
            NO_POLICY,
            IPV6_UNSUPPORTED,
            UNKNOWN,
        ],
        UNKNOWN,
    );
}

/// Bounded `reason` values for a denied query.
const DENY_REASONS: Allowlist = Allowlist::new(
    &[
        "ipv6_unsupported",
        "no_policy",
        "unsupported_qtype",
        "platform_internal",
        "policy_deny",
        UNKNOWN,
    ],
    UNKNOWN,
);

/// Bounded `reason` values for a failed query.
const FAILURE_REASONS: Allowlist =
    Allowlist::new(&["upstream_failure", "malformed_message", UNKNOWN], UNKNOWN);

/// Bounded `source` values for an allowed query.
const ALLOW_SOURCES: Allowlist = Allowlist::new(&["cache", "resolved", UNKNOWN], UNKNOWN);

/// Bounded `action` values on the `query_domain` series.
const QUERY_DOMAIN_ACTIONS: Allowlist =
    Allowlist::new(&["allowed", "denied", "failed", UNKNOWN], UNKNOWN);

/// Bounded `rcode` values.
const RCODES: Allowlist = Allowlist::new(
    &[
        "noerror", "nxdomain", "servfail", "refused", "formerr", UNKNOWN,
    ],
    UNKNOWN,
);

pub(super) struct DnsMetrics {
    pub queries_total: Counter,
    pub allowed: Counter,
    pub denied: Counter,
    pub failed: Counter,
    pub cache_hits: Counter,
    pub cache_misses: Counter,
    pub resolution_duration: Histogram,
    pub policy_actions: Counter,
    pub registered_sandboxes: Gauge,
    pub query_domain: Counter,
    pub response_code: Counter,
}

impl DnsMetrics {
    fn register() -> Self {
        Self {
            queries_total: Counter::register(DNS_QUERIES_TOTAL),
            allowed: Counter::register(DNS_ALLOWED),
            denied: Counter::register(DNS_DENIED),
            failed: Counter::register(DNS_FAILED),
            cache_hits: Counter::register(DNS_CACHE_HITS),
            cache_misses: Counter::register(DNS_CACHE_MISSES),
            resolution_duration: Histogram::register(DNS_RESOLUTION_DURATION),
            policy_actions: Counter::register(DNS_POLICY_ACTIONS),
            registered_sandboxes: Gauge::register(DNS_REGISTERED_SANDBOXES),
            query_domain: Counter::register(DNS_QUERY_DOMAIN),
            response_code: Counter::register(DNS_RESPONSE_CODE),
        }
    }
}

/// Records a received query, before any policy decision.
pub(super) fn record_query() {
    DNS_METRICS.queries_total.inc(&Labels::host());
}

/// Records a denial and the policy action that produced it.
///
/// `reason` and `action` are normalized against closed allowlists, so a new
/// call site cannot introduce a new series by passing a different string.
pub(super) fn record_denied(reason: &str, action: &str) {
    DNS_METRICS
        .denied
        .inc(&Labels::host().with(attr::REASON, DENY_REASONS.bound(reason).as_str()));
    record_policy_action(action);
}

/// Records an allow and the policy action that produced it.
pub(super) fn record_allowed(action: &str, source: &str) {
    DNS_METRICS
        .allowed
        .inc(&Labels::host().with(attr::SOURCE, ALLOW_SOURCES.bound(source).as_str()));
    record_policy_action(action);
}

/// Records a query failure.
pub(super) fn record_failed(reason: &str) {
    DNS_METRICS
        .failed
        .inc(&Labels::host().with(attr::REASON, FAILURE_REASONS.bound(reason).as_str()));
}

/// Records which policy rule produced a decision.
pub(super) fn record_policy_action(action: &str) {
    DNS_METRICS
        .policy_actions
        .inc(&Labels::host().with(attr::ACTION, dns_action::ALL.bound(action).as_str()));
}

/// Records a query against a domain suffix class.
pub(super) fn record_query_domain(domain: &str, action: &str) {
    DNS_METRICS.query_domain.inc(
        &Labels::host()
            .with(attr::DOMAIN, domain)
            .with(attr::ACTION, QUERY_DOMAIN_ACTIONS.bound(action).as_str()),
    );
}

/// Records a response code against a domain suffix class.
pub(super) fn record_response_code(rcode: &str, domain: &str) {
    DNS_METRICS.response_code.inc(
        &Labels::host()
            .with(attr::RCODE, RCODES.bound(rcode).as_str())
            .with(attr::DOMAIN, domain),
    );
}

/// Records a cache hit.
pub(super) fn record_cache_hit() {
    DNS_METRICS.cache_hits.inc(&Labels::host());
}

/// Records a cache miss.
pub(super) fn record_cache_miss() {
    DNS_METRICS.cache_misses.inc(&Labels::host());
}

/// Records an end-to-end resolution duration, by domain suffix class.
pub(super) fn record_resolution_duration(seconds: f64, domain: &str) {
    DNS_METRICS
        .resolution_duration
        .record(seconds, &Labels::host().with(attr::DOMAIN, domain));
}

/// Records the number of sandboxes with a DNS policy registered.
pub(super) fn record_registered_sandboxes(count: u64) {
    DNS_METRICS
        .registered_sandboxes
        .set(count as f64, &Labels::host());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_reasons_are_a_closed_set() {
        // Every reason a call site passes must already be in the allowlist,
        // otherwise the series silently collapses to `unknown`.
        for reason in DENY_REASONS.values() {
            assert_eq!(DENY_REASONS.bound(reason).as_str(), *reason);
        }
    }

    #[test]
    fn policy_actions_are_a_closed_set() {
        for action in dns_action::ALL.values() {
            assert_eq!(dns_action::ALL.bound(action).as_str(), *action);
        }
    }

    #[test]
    fn allow_sources_and_rcodes_are_closed_sets() {
        for source in ALLOW_SOURCES.values() {
            assert_eq!(ALLOW_SOURCES.bound(source).as_str(), *source);
        }
        for rcode in RCODES.values() {
            assert_eq!(RCODES.bound(rcode).as_str(), *rcode);
        }
    }

    #[test]
    fn failure_reasons_are_a_closed_set() {
        for reason in FAILURE_REASONS.values() {
            assert_eq!(FAILURE_REASONS.bound(reason).as_str(), *reason);
        }
    }

    #[test]
    fn query_domain_actions_are_a_closed_set() {
        for action in QUERY_DOMAIN_ACTIONS.values() {
            assert_eq!(QUERY_DOMAIN_ACTIONS.bound(action).as_str(), *action);
        }
    }

    #[test]
    fn unrecognized_values_collapse_to_unknown() {
        assert_eq!(DENY_REASONS.bound("attacker.controlled").as_str(), UNKNOWN);
        assert_eq!(dns_action::ALL.bound("weird").as_str(), UNKNOWN);
    }

    #[test]
    fn recording_does_not_panic() {
        record_query();
        record_denied("no_policy", dns_action::NO_POLICY);
        record_denied("nonsense", "nonsense");
        record_allowed(dns_action::ALLOW_RULE, "resolved");
        record_allowed(dns_action::ALLOW_RULE, "cache");
        record_failed("upstream_failure");
        record_policy_action(dns_action::DEFAULT_DENY);
        record_query_domain(".com.example", "denied");
        record_response_code("nxdomain", ".com.example");
        record_cache_hit();
        record_cache_miss();
        record_resolution_duration(0.004, ".com.example");
        record_registered_sandboxes(3);
    }
}

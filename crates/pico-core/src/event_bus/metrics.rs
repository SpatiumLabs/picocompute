//! Audit pipeline health metrics.
//!
//! Per ADR-0009, audit pipeline metrics provide visibility into delivery
//! health, backlog, and end-to-end lag.

use std::sync::LazyLock;

use pico_telemetry::metrics::{Allowlist, Counter, Gauge, Histogram, Labels, attr};

/// Audit pipeline metrics registered at startup.
pub static AUDIT_PIPELINE_METRICS: LazyLock<AuditPipelineMetrics> =
    LazyLock::new(AuditPipelineMetrics::register);

const DELIVERY_COUNT: &str = "pico.audit.delivery.count";
const DELIVERY_LAG: &str = "pico.audit.delivery.lag";
const OUTBOX_PENDING: &str = "pico.audit.outbox.pending";

pub struct AuditPipelineMetrics {
    pub delivery_count: Counter,
    pub delivery_lag: Histogram,
    pub outbox_pending: Gauge,
}

impl AuditPipelineMetrics {
    fn register() -> Self {
        Self {
            delivery_count: Counter::register(DELIVERY_COUNT),
            delivery_lag: Histogram::register(DELIVERY_LAG),
            outbox_pending: Gauge::register(OUTBOX_PENDING),
        }
    }
}

/// Fallback for a label value outside the allowlists below.
const UNKNOWN: &str = "unknown";

/// Bounded `outcome` label values for audit delivery.
///
/// Keeping this closed is what stops an error string from becoming a label value
/// and inflating cardinality without bound. `UNKNOWN` is a member so an
/// unrecognised value normalizes to something still inside the set; the
/// compiler rejects a set that omits its own fallback.
const DELIVERY_OUTCOMES: Allowlist = Allowlist::new(
    &["delivered", "retry", "dead_letter", "dropped", UNKNOWN],
    UNKNOWN,
);

/// Bounded `reason` label values for audit delivery failures.
const DELIVERY_REASONS: Allowlist = Allowlist::new(
    &["backpressure", "serialization", "sink_error", UNKNOWN],
    UNKNOWN,
);

/// Record delivery of audit events.
///
/// `outcome` and `reason` are normalized against closed allowlists, so an error
/// string can never become a label value. `reason` is only attached when present.
pub fn record_audit_delivery(batch_size: usize, outcome: &str, reason: Option<&str>) {
    let mut labels = Labels::host().with(attr::OUTCOME, DELIVERY_OUTCOMES.bound(outcome).as_str());
    if let Some(reason) = reason {
        labels = labels.with(attr::REASON, DELIVERY_REASONS.bound(reason).as_str());
    }
    AUDIT_PIPELINE_METRICS
        .delivery_count
        .inc_by(batch_size as u64, &labels);
}

/// Record a delivery lag in seconds (wall-clock time from event generation
/// to persistence confirmation).
pub fn record_audit_delivery_lag(lag_seconds: f64) {
    AUDIT_PIPELINE_METRICS
        .delivery_lag
        .record(lag_seconds, &Labels::host());
}

/// Record the current outbox pending count.
///
/// Note: this reflects the most recently observed batch size rather than
/// the full channel depth because `tokio::sync::mpsc` does not expose a
/// channel length. For true backlog monitoring, emit this from the producer
/// side where the backlog is known.
pub fn record_audit_outbox_pending(count: u64) {
    AUDIT_PIPELINE_METRICS
        .outbox_pending
        .set(count as f64, &Labels::host());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Captures what the audit delivery series would be labelled with, by
    /// rebuilding the label set the way `record_audit_delivery` does.
    fn delivery_labels<'a>(outcome: &'a str, reason: Option<&'a str>) -> Labels<'a> {
        let mut labels =
            Labels::host().with(attr::OUTCOME, DELIVERY_OUTCOMES.bound(outcome).as_str());
        if let Some(reason) = reason {
            labels = labels.with(attr::REASON, DELIVERY_REASONS.bound(reason).as_str());
        }
        labels
    }

    fn pairs<'l, 'a>(labels: &'l Labels<'a>) -> Vec<(&'static str, &'l str)> {
        labels.as_slice().to_vec()
    }

    #[test]
    fn allowlisted_outcome_is_kept() {
        let labels = delivery_labels("delivered", None);
        assert_eq!(pairs(&labels), vec![(attr::OUTCOME.as_str(), "delivered")]);
    }

    #[test]
    fn unbounded_outcome_falls_back_to_unknown() {
        // An error string reaching `outcome` must not become a label value.
        let labels = delivery_labels("connection refused on 10.0.3.7:5432", None);
        assert_eq!(pairs(&labels), vec![(attr::OUTCOME.as_str(), "unknown")]);
    }

    #[test]
    fn unbounded_reason_falls_back_to_unknown() {
        let labels = delivery_labels("retry", Some("pool exhausted at line 42"));
        assert_eq!(
            pairs(&labels),
            vec![
                (attr::OUTCOME.as_str(), "retry"),
                (attr::REASON.as_str(), "unknown")
            ]
        );
    }

    #[test]
    fn reason_is_omitted_when_absent() {
        let labels = delivery_labels("dropped", None);
        assert!(
            !pairs(&labels)
                .iter()
                .any(|(k, _)| *k == attr::REASON.as_str())
        );
    }

    #[test]
    fn every_allowlist_normalizes_out_of_set_input_to_a_member() {
        // The invariant the type now enforces: whatever goes in comes out
        // either unchanged or as the set's own fallback.
        for input in [
            "delivered",
            "retry",
            "dead_letter",
            "dropped",
            "unknown",
            "connection refused on 10.0.3.7:5432",
            "",
        ] {
            assert!(
                DELIVERY_OUTCOMES
                    .values()
                    .contains(&DELIVERY_OUTCOMES.bound(input).as_str())
            );
        }
        for input in [
            "backpressure",
            "serialization",
            "sink_error",
            "pool exhausted",
        ] {
            assert!(
                DELIVERY_REASONS
                    .values()
                    .contains(&DELIVERY_REASONS.bound(input).as_str())
            );
        }
    }

    #[test]
    fn delivery_metrics_record_without_panic() {
        record_audit_delivery(4, "delivered", None);
        record_audit_delivery(1, "retry", Some("backpressure"));
        record_audit_delivery(0, "something-unexpected", Some("also-unexpected"));
        record_audit_delivery_lag(0.25);
        record_audit_outbox_pending(17);
    }
}

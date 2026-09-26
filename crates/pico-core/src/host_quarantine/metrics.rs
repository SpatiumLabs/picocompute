//! Quarantine alert observability metrics.

use std::sync::LazyLock;

use pico_telemetry::metrics::{Counter, Gauge};

const ALERTS_FIRED_TOTAL: &str = "pico_quarantine_alerts_fired_total";
const ALERTS_RESOLVED_TOTAL: &str = "pico_quarantine_alerts_resolved_total";
const ALERTS_ACTIVE: &str = "pico_quarantine_alerts_active";
const HOSTS_QUARANTINED: &str = "pico_quarantine_hosts_quarantined";

pub static QUARANTINE_METRICS: LazyLock<QuarantineMetrics> =
    LazyLock::new(QuarantineMetrics::register);

pub struct QuarantineMetrics {
    pub alerts_fired: Counter,
    pub alerts_resolved: Counter,
    pub alerts_active: Gauge,
    pub hosts_quarantined: Gauge,
}

impl QuarantineMetrics {
    fn register() -> Self {
        Self {
            alerts_fired: Counter::register(ALERTS_FIRED_TOTAL),
            alerts_resolved: Counter::register(ALERTS_RESOLVED_TOTAL),
            alerts_active: Gauge::register(ALERTS_ACTIVE),
            hosts_quarantined: Gauge::register(HOSTS_QUARANTINED),
        }
    }
}

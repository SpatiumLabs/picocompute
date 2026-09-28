//! Metrics primitives, the shared-host redaction policy, and the OTLP gRPC
//! exporter.
//!
//! # Label ownership
//!
//! Every data point is recorded with a [`Labels`] set rather than a free-form
//! attribute slice. [`Labels`] is the only construction path for an identity
//! attribute (`tenant_id` / `sandbox_id`), so the shared-host redaction
//! decision in [`redaction`] cannot be bypassed by a call site that builds its
//! own slice. See [`labels`] for the three identity policies.
//!
//! ```rust
//! # use pico_telemetry::metrics::{Counter, Labels};
//! let created = Counter::register("pico_create_events_total");
//! // Host-level aggregate: never attributed.
//! created.inc(&Labels::host());
//! // Sandbox-scoped: sandbox_id on a dedicated host, tenant_id on a shared one.
//! created.inc(&Labels::sandbox("sbx_1", Some("tnt_1")));
//! ```

mod labels;
mod rate_limit;
mod redaction;

use core::time::Duration;
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig as _;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use parking_lot::Mutex;
use std::sync::LazyLock;

use crate::BoxError;
use crate::settings::MetricsSettings;

pub use labels::{Allowlist, Bounded, Labels, PlainKey};
pub use rate_limit::{RateLimiter, SHARED_HOST_LIMITER};
pub use redaction::{set_shared_host_redaction, shared_host_redaction};

/// Shared metric attribute key constants.
///
/// Every non-identity key is a [`PlainKey`], and the two identity keys are
/// plain strings. That split is what stops [`Labels::with`](super::Labels::with)
/// from accepting an identity key, so redaction cannot be bypassed by handing a
/// label set a hand-built `tenant_id`.
pub mod attr {
    use super::PlainKey;

    /// Network or device type (tap, veth, route, namespace).
    pub const KIND: PlainKey = PlainKey::new("kind");
    /// Backend runtime class (microvm, container).
    pub const BACKEND: PlainKey = PlainKey::new("backend");
    /// Failure or skip reason.
    pub const REASON: PlainKey = PlainKey::new("reason");
    /// Boot lifecycle event name.
    pub const EVENT: PlainKey = PlainKey::new("event");
    /// Boot outcome status (ready, not_ready).
    pub const STATUS: PlainKey = PlainKey::new("status");
    /// Lifecycle operation name (create, boot, exec, destroy, etc.).
    pub const OPERATION: PlainKey = PlainKey::new("operation");
    /// Lifecycle outcome (success, timeout, cancelled, runtime_failed, etc.).
    pub const OUTCOME: PlainKey = PlainKey::new("outcome");
    /// Interface name (e.g. `cvx0`).
    pub const IF_NAME: PlainKey = PlainKey::new("if_name");
    /// Platform-assigned host identifier.
    ///
    /// Not a tenancy attribute: a host is the unit that isolates tenants, so
    /// host-scoped series are safe to publish on shared hosts.
    pub const HOST_ID: PlainKey = PlainKey::new("host_id");
    /// Alert severity (`info`, `warning`, `critical`).
    pub const SEVERITY: PlainKey = PlainKey::new("severity");
    /// Alert or health condition name.
    pub const CONDITION: PlainKey = PlainKey::new("condition");
    /// Capacity dimension (`total`, `allocated`, `used`).
    pub const STATE: PlainKey = PlainKey::new("state");
    /// Resource whose utilization is reported (`cpu`, `memory`, `disk`, ...).
    pub const RESOURCE: PlainKey = PlainKey::new("resource");
    /// Current health of a host or subsystem.
    pub const HEALTH_STATE: PlainKey = PlainKey::new("health_state");
    /// Image cache lookup result (`hit`, `miss`, `evicted`, `unknown`).
    /// Bounded allowlist only; never use image digests or IDs as label values.
    pub const CACHE_RESULT: PlainKey = PlainKey::new("cache_result");
    /// Guest image profile (`minimal`, `agent`, `session`, `unknown`).
    /// Bounded allowlist only.
    pub const IMAGE_PROFILE: PlainKey = PlainKey::new("image_profile");
    /// Queried DNS domain suffix class, e.g. `.com.example`. Never the queried
    /// name itself.
    pub const DOMAIN: PlainKey = PlainKey::new("domain");
    /// DNS response code.
    pub const RCODE: PlainKey = PlainKey::new("rcode");
    /// DNS policy action taken.
    pub const ACTION: PlainKey = PlainKey::new("action");
    /// How a DNS query was answered.
    pub const SOURCE: PlainKey = PlainKey::new("source");
    /// Syscall name, for the syscall-latency histogram.
    pub const SYSCALL: PlainKey = PlainKey::new("syscall");
    /// Image cache tier (`host_local`, `cell_cache`, ...).
    /// Bounded allowlist only.
    pub const TIER: PlainKey = PlainKey::new("tier");

    // ── Identity keys ──
    //
    // Deliberately `&'static str` and not `PlainKey`, so they cannot be passed
    // to `Labels::with`. Only the `Labels` policy constructors attach these.

    /// Tenant identifier for shared-host metric redaction mode.
    ///
    /// Attached only by [`Labels`](super::Labels), never by hand.
    pub const TENANT_ID: &str = "tenant_id";
    /// Sandbox identifier (excluded in shared-host metric redaction mode).
    ///
    /// Attached only by [`Labels`](super::Labels), never by hand.
    pub const SANDBOX_ID: &str = "sandbox_id";
}

static METER_PROVIDER: LazyLock<Mutex<Option<SdkMeterProvider>>> =
    LazyLock::new(|| Mutex::new(None));

pub(crate) fn init_exporter(
    settings: &MetricsSettings,
) -> Result<Option<SdkMeterProvider>, BoxError> {
    if settings.otlp_endpoint.is_empty() {
        return Ok(None);
    }

    let exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_tonic()
        .with_endpoint(&settings.otlp_endpoint)
        .build()
        .map_err(|e| Box::new(e) as BoxError)?;

    let mut resource_attrs: Vec<KeyValue> =
        vec![KeyValue::new("service.name", settings.service_name.clone())];
    resource_attrs.extend(
        settings
            .resource_attributes
            .iter()
            .map(|(k, v)| KeyValue::new(k.clone(), v.clone())),
    );

    let resource = opentelemetry_sdk::Resource::builder()
        .with_attributes(resource_attrs)
        .build();

    let reader = PeriodicReader::builder(exporter)
        .with_interval(Duration::from_secs(settings.export_interval_secs))
        .build();

    let provider = SdkMeterProvider::builder()
        .with_resource(resource)
        .with_reader(reader)
        .build();

    opentelemetry::global::set_meter_provider(provider.clone());

    let mut guard = METER_PROVIDER.lock();
    *guard = Some(provider.clone());

    Ok(Some(provider))
}

pub(crate) fn shutdown_metrics() {
    if let Some(provider) = METER_PROVIDER.lock().take() {
        let _ = provider.shutdown();
    }
}

/// Builds the OpenTelemetry attributes for a label set.
///
/// Keys are `&'static str`, so they convert into a borrowed `Cow` without
/// allocating; only the value, which is borrowed from the call site, needs an
/// owned copy. This allocation is on the SDK's own boundary and was present
/// before label sets were typed, so it is not a regression.
fn key_values(labels: &Labels<'_>) -> Vec<KeyValue> {
    labels
        .as_slice()
        .iter()
        .map(|(k, v)| KeyValue::new(*k, (*v).to_owned()))
        .collect()
}

/// Counter metric.
pub struct Counter {
    inner: opentelemetry::metrics::Counter<u64>,
}

impl Counter {
    pub fn register(name: &'static str) -> Self {
        let meter = opentelemetry::global::meter("pico");
        let inner = meter.u64_counter(name).build();
        Self { inner }
    }

    pub fn inc(&self, labels: &Labels<'_>) {
        self.add(1, labels);
    }

    /// Increments the counter by an explicit amount.
    pub fn inc_by(&self, value: u64, labels: &Labels<'_>) {
        self.add(value, labels);
    }

    fn add(&self, value: u64, labels: &Labels<'_>) {
        self.inner.add(value, &key_values(labels));
    }
}

/// Histogram metric.
pub struct Histogram {
    inner: opentelemetry::metrics::Histogram<f64>,
}

impl Histogram {
    pub fn register(name: &'static str) -> Self {
        let meter = opentelemetry::global::meter("pico");
        let inner = meter.f64_histogram(name).build();
        Self { inner }
    }

    pub fn record(&self, value: f64, labels: &Labels<'_>) {
        self.inner.record(value, &key_values(labels));
    }
}

/// Gauge metric.
pub struct Gauge {
    inner: opentelemetry::metrics::Gauge<f64>,
}

impl Gauge {
    pub fn register(name: &'static str) -> Self {
        let meter = opentelemetry::global::meter("pico");
        let inner = meter.f64_gauge(name).build();
        Self { inner }
    }

    pub fn set(&self, value: f64, labels: &Labels<'_>) {
        self.inner.record(value, &key_values(labels));
    }
}

/// Serializes tests that mutate process-global metric state.
///
/// The redaction flag is a single process-wide `AtomicBool`, so under plain
/// `cargo test` - where tests share a process and run on parallel threads - two
/// tests that each flip it can observe each other's value. `nextest` isolates
/// every test in its own process, which is why the suite passes either way, but
/// relying on that alone makes a failure depend on the runner.
///
/// `parking_lot` so a panicking test cannot poison the lock and cascade into
/// unrelated failures.
#[cfg(test)]
pub(crate) static STATE_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

/// Test helper: initialize an in-memory exporter for assertions.
#[cfg(test)]
pub fn init_test() {
    // no-op in test mode - metrics are recorded via global but not exported
    let provider = opentelemetry_sdk::metrics::SdkMeterProvider::builder().build();
    opentelemetry::global::set_meter_provider(provider);
}

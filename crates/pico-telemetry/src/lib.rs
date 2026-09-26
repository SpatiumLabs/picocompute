//! Standardized telemetry: log, metrics, and tracing with OTLP export.
//!
//! # Usage
//!
//! ```rust,no_run
//! use pico_telemetry::{TelemetryConfig, TelemetrySettings};
//!
//! let config = TelemetryConfig {
//!     settings: &TelemetrySettings::default(),
//! };
//! let driver = pico_telemetry::init(config).expect("telemetry init");
//! tokio::spawn(driver);
//! ```

mod settings;

pub mod events;
pub mod lifecycle;
pub mod log;
pub mod metrics;
pub mod structured_log;
pub mod trace_context;
pub mod tracing;

use std::sync::atomic::{AtomicBool, Ordering};
use thiserror::Error;
use tracing_subscriber::{Registry, fmt, layer::SubscriberExt, util::SubscriberInitExt};

static INITIALIZED: AtomicBool = AtomicBool::new(false);
pub(crate) type BoxError = Box<dyn std::error::Error + Send + Sync>;

pub use settings::{LogFormat, LogSettings, MetricsSettings, TelemetrySettings, TracingSettings};

/// Configuration passed to [`init`].
pub struct TelemetryConfig<'c> {
    pub settings: &'c TelemetrySettings,
}

/// Handle driving async telemetry export.
///
/// On drop, flushes and shuts down both the metrics and tracing OTLP exporters
/// so buffered data is not lost on process exit.
pub struct TelemetryDriver;

impl Drop for TelemetryDriver {
    fn drop(&mut self) {
        metrics::shutdown_metrics();
        tracing::shutdown_tracing();
    }
}

impl std::future::Future for TelemetryDriver {
    type Output = ();

    fn poll(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        std::task::Poll::Pending
    }
}

#[derive(Debug, Error)]
pub enum TelemetryError {
    #[error("pico_telemetry::init() already called at {file}:{line}:{column}")]
    AlreadyInitialized {
        file: &'static str,
        line: u32,
        column: u32,
    },
    #[error("failed to initialize metrics exporter: {0}")]
    Metrics(BoxError),
    #[error("failed to initialize tracing: {0}")]
    Tracing(BoxError),
}

/// Initializes telemetry. Call once at process startup.
#[track_caller]
pub fn init(config: TelemetryConfig) -> Result<TelemetryDriver, TelemetryError> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        let loc = std::panic::Location::caller();
        return Err(TelemetryError::AlreadyInitialized {
            file: loc.file(),
            line: loc.line(),
            column: loc.column(),
        });
    }

    let filter = log::create_filter(&config.settings.log);
    let otel_tracing_layer = tracing::init_layer(
        &config.settings.tracing,
        &config.settings.metrics.service_name,
    )
    .map_err(TelemetryError::Tracing)?;

    match config.settings.log.format {
        LogFormat::Pretty => {
            let base = Registry::default();
            if let Some(otel_layer) = otel_tracing_layer {
                base.with(otel_layer)
                    .with(filter)
                    .with(fmt::layer().pretty())
                    .init();
            } else {
                base.with(filter).with(fmt::layer().pretty()).init();
            }
        }
        LogFormat::Json => {
            let base = Registry::default();
            if let Some(otel_layer) = otel_tracing_layer {
                base.with(otel_layer)
                    .with(filter)
                    .with(fmt::layer().json())
                    .init();
            } else {
                base.with(filter).with(fmt::layer().json()).init();
            }
        }
    }

    let _meter_provider =
        metrics::init_exporter(&config.settings.metrics).map_err(TelemetryError::Metrics)?;

    Ok(TelemetryDriver)
}

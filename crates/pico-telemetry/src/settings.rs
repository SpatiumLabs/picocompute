//! Telemetry configuration.

/// Top-level telemetry settings.
#[derive(Clone, Debug, Default)]
pub struct TelemetrySettings {
    pub log: LogSettings,
    pub metrics: MetricsSettings,
    pub tracing: TracingSettings,
}

#[derive(Clone, Debug)]
pub struct LogSettings {
    pub format: LogFormat,
    pub filter: String,
    /// Substrings that trigger credential redaction (case-insensitive matching).
    pub credential_redaction_patterns: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct MetricsSettings {
    /// OTLP gRPC collector endpoint (empty = no export).
    pub otlp_endpoint: String,
    /// Export interval in seconds.
    pub export_interval_secs: u64,
    /// Service name prefix.
    pub service_name: String,
    /// Extra resource attributes (key, value pairs).
    pub resource_attributes: Vec<(String, String)>,
}

#[derive(Clone, Debug, Default)]
pub struct TracingSettings {
    /// OTLP gRPC endpoint for spans (empty = no export).
    pub otlp_endpoint: String,
    /// Sample rate 0.0-1.0.
    pub sample_rate: f64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LogFormat {
    #[default]
    Pretty,
    Json,
}

impl Default for LogSettings {
    fn default() -> Self {
        Self {
            format: LogFormat::default(),
            filter: "info".to_string(),
            credential_redaction_patterns: vec![
                "token".into(),
                "secret".into(),
                "password".into(),
                "api_key".into(),
                "private_key".into(),
            ],
        }
    }
}

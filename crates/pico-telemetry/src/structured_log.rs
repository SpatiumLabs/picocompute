//! Structured platform log contracts.
//!
//! Every record follows the canonical schema defined in ADR-0009:
//! timestamp, severity, service identity, region/cell/host, trace and span IDs,
//! correlation IDs, lifecycle state, backend, outcome, reason, and redaction
//! markers. Sensitive values are removed before emission via the [`Redacted`]
//! wrapper and the source-side allowlist.
//!
//! # Dual-emission strategy
//!
//! Lifecycle events in `boot.rs` emit two tracing records per event:
//!
//! 1. A **structured platform log** via [`LogRecord::emit`] targeting
//!    `pico_platform_log`. These carry `severity_number`, strongly-typed
//!    outcome/reason taxonomy, correlation IDs, and optional redaction
//!    metadata. Filter by `target = "pico_platform_log"` for aggregation.
//!
//! 2. A **human-readable diagnostic event** via bare `tracing::info!` etc.
//!    These carry ephemeral detail (latency_ms, policy_epoch, diagnostics)
//!    that aids operational debugging but is not part of the canonical
//!    platform log schema. Filter by *absence* of `target` or
//!    `target = module_path` for interactive inspection.
//!
//! The dual strategy keeps the platform log schema stable for downstream
//! consumers (dashboards, alerts, audit enrichment) while preserving rich
//! ad-hoc diagnostic data for operators.

use serde::Serialize;

use crate::lifecycle::LifecycleOperation;

/// Marks a field whose value has been intentionally removed before emission.
///
/// Serializes as `{ "redacted": true }` so downstream consumers can
/// distinguish between a missing field and a deliberately removed one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redacted<T> {
    _phantom: std::marker::PhantomData<T>,
}

impl<T> Redacted<T> {
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<T> Default for Redacted<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Serialize for Redacted<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("Redacted", 1)?;
        s.serialize_field("redacted", &true)?;
        s.end()
    }
}

/// Log severity levels aligned with OpenTelemetry severity numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum LogSeverity {
    #[serde(rename = "TRACE")]
    Trace,
    #[serde(rename = "DEBUG")]
    Debug,
    #[serde(rename = "INFO")]
    Info,
    #[serde(rename = "WARN")]
    Warn,
    #[serde(rename = "ERROR")]
    Error,
}

impl LogSeverity {
    pub const fn severity_number(self) -> u8 {
        match self {
            Self::Trace => 1,
            Self::Debug => 5,
            Self::Info => 9,
            Self::Warn => 13,
            Self::Error => 17,
        }
    }
}

impl std::fmt::Display for LogSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Trace => "TRACE",
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
        })
    }
}

/// Structured platform log record conforming to ADR-0009 schema.
///
/// Every record includes timestamp, severity, service identity, and
/// optional correlation IDs. Fields that carry sensitive data use the
/// [`Redacted`] wrapper to mark intentional removal.
#[derive(Debug, Clone, Serialize)]
pub struct LogRecord {
    /// ISO-8601 timestamp of the event.
    pub timestamp: String,

    /// Log severity level.
    pub severity: LogSeverity,
    #[serde(rename = "severity_number")]
    pub severity_num: u8,

    /// Stable event name for filtering (e.g. "boot_not_ready").
    pub event: String,

    /// Human-readable message template (no variable interpolation).
    pub message: String,

    // ── Service and deployment identity ──
    #[serde(rename = "service.name")]
    pub service_name: String,
    #[serde(rename = "service.version")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_version: Option<String>,

    // ── Location identity ──
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(rename = "cell_id")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cell_id: Option<String>,
    #[serde(rename = "host_id")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_id: Option<String>,

    // ── Trace and span correlation ──
    #[serde(rename = "trace_id")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(rename = "span_id")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub span_id: Option<String>,

    // ── Operation correlation IDs ──
    #[serde(rename = "operation_id")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    #[serde(rename = "request_id")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(rename = "tenant_id")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(rename = "sandbox_id")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox_id: Option<String>,

    // ── Lifecycle taxonomy ──
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    #[serde(rename = "lifecycle_state")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifecycle_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    // ── Component ──
    #[serde(skip_serializing_if = "Option::is_none")]
    pub component: Option<String>,
    #[serde(rename = "source_location")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_location: Option<String>,

    // ── Redaction metadata ──
    #[serde(default)]
    pub redacted: bool,
    #[serde(rename = "redacted_fields")]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redacted_fields: Vec<String>,
}

macro_rules! emit_record {
    ($self:expr, $level:ident, $message:expr) => {{
        tracing::$level!(
            target: "pico_platform_log",
            event = %$self.event,
            timestamp = %$self.timestamp,
            severity = %$self.severity,
            severity_number = $self.severity_num,
            service_name = %$self.service_name,
            sandbox_id = $self.sandbox_id.as_deref(),
            operation_id = $self.operation_id.as_deref(),
            host_id = $self.host_id.as_deref(),
            cell_id = $self.cell_id.as_deref(),
            region = $self.region.as_deref(),
            outcome = $self.outcome.as_deref(),
            reason = $self.reason.as_deref(),
            lifecycle_state = $self.lifecycle_state.as_deref(),
            backend = $self.backend.as_deref(),
            component = $self.component.as_deref(),
            redacted = $self.redacted,
            redacted_fields = ?$self.redacted_fields,
            "{}",
            $message
        )
    }};
}

impl LogRecord {
    /// Emits this record through the tracing subscriber at the matching level.
    pub fn emit(&self) {
        let message = self.message.clone();
        match self.severity {
            LogSeverity::Error => emit_record!(self, error, message),
            LogSeverity::Warn => emit_record!(self, warn, message),
            LogSeverity::Info => emit_record!(self, info, message),
            LogSeverity::Debug => emit_record!(self, debug, message),
            LogSeverity::Trace => emit_record!(self, trace, message),
        }
    }

    /// Serializes this record to a JSON string.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

/// Builder for constructing [`LogRecord`] entries.
///
/// ```rust
/// # use pico_telemetry::structured_log::{LogRecordBuilder, LogSeverity};
/// let record = LogRecordBuilder::new("my_service", "boot_not_ready", "sandbox boot did not become ready")
///     .severity(LogSeverity::Error)
///     .sandbox_id("sbx_01abc")
///     .operation_id("opr_01def")
///     .host_id("host-1")
///     .cell_id("cell-a")
///     .region("us-east-1")
///     .outcome("protocol_error")
///     .reason("protocol")
///     .lifecycle_state("Failed")
///     .backend("firecracker")
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct LogRecordBuilder {
    record: LogRecord,
}

impl LogRecordBuilder {
    pub fn new(
        service_name: impl Into<String>,
        event: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            record: LogRecord {
                timestamp: chrono_now(),
                severity: LogSeverity::Info,
                severity_num: LogSeverity::Info.severity_number(),
                event: event.into(),
                message: message.into(),
                service_name: service_name.into(),
                service_version: None,
                region: None,
                cell_id: None,
                host_id: None,
                trace_id: None,
                span_id: None,
                operation_id: None,
                request_id: None,
                tenant_id: None,
                sandbox_id: None,
                operation: None,
                phase: None,
                lifecycle_state: None,
                backend: None,
                outcome: None,
                reason: None,
                component: None,
                source_location: None,
                redacted: false,
                redacted_fields: Vec::new(),
            },
        }
    }

    pub fn severity(mut self, severity: LogSeverity) -> Self {
        self.record.severity = severity;
        self.record.severity_num = severity.severity_number();
        self
    }

    pub fn service_version(mut self, v: impl Into<String>) -> Self {
        self.record.service_version = Some(v.into());
        self
    }

    pub fn region(mut self, v: impl Into<String>) -> Self {
        self.record.region = Some(v.into());
        self
    }

    pub fn cell_id(mut self, v: impl Into<String>) -> Self {
        self.record.cell_id = Some(v.into());
        self
    }

    pub fn host_id(mut self, v: impl Into<String>) -> Self {
        self.record.host_id = Some(v.into());
        self
    }

    pub fn trace_id(mut self, v: impl Into<String>) -> Self {
        self.record.trace_id = Some(v.into());
        self
    }

    pub fn span_id(mut self, v: impl Into<String>) -> Self {
        self.record.span_id = Some(v.into());
        self
    }

    pub fn operation_id(mut self, v: impl Into<String>) -> Self {
        self.record.operation_id = Some(v.into());
        self
    }

    pub fn request_id(mut self, v: impl Into<String>) -> Self {
        self.record.request_id = Some(v.into());
        self
    }

    pub fn tenant_id(mut self, v: impl Into<String>) -> Self {
        self.record.tenant_id = Some(v.into());
        self
    }

    pub fn sandbox_id(mut self, v: impl Into<String>) -> Self {
        self.record.sandbox_id = Some(v.into());
        self
    }

    pub fn operation(mut self, op: LifecycleOperation) -> Self {
        self.record.operation = Some(op.as_str().to_string());
        self
    }

    pub fn phase(mut self, v: impl Into<String>) -> Self {
        self.record.phase = Some(v.into());
        self
    }

    pub fn lifecycle_state(mut self, v: impl Into<String>) -> Self {
        self.record.lifecycle_state = Some(v.into());
        self
    }

    pub fn backend(mut self, v: impl Into<String>) -> Self {
        self.record.backend = Some(v.into());
        self
    }

    pub fn outcome(mut self, v: impl Into<String>) -> Self {
        self.record.outcome = Some(v.into());
        self
    }

    pub fn reason(mut self, v: impl Into<String>) -> Self {
        self.record.reason = Some(v.into());
        self
    }

    pub fn component(mut self, v: impl Into<String>) -> Self {
        self.record.component = Some(v.into());
        self
    }

    pub fn source_location(mut self, v: impl Into<String>) -> Self {
        self.record.source_location = Some(v.into());
        self
    }

    /// Marks specific fields as redacted. The record's `redacted` flag is set to `true`.
    pub fn with_redacted_fields(mut self, fields: Vec<String>) -> Self {
        self.record.redacted = true;
        self.record.redacted_fields = fields;
        self
    }

    pub fn build(self) -> LogRecord {
        self.record
    }
}

/// Returns an ISO-8601 timestamp string for the current UTC time.
fn chrono_now() -> String {
    let now: chrono::DateTime<chrono::Utc> = chrono::Utc::now();
    now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Redaction helper: replaces a value with [`Redacted`] and records the field name.
///
/// Used when a field would normally contain sensitive data (credentials, paths,
/// commands, etc.) and must be excluded from platform logs.
pub fn redact<T>(_value: T, field_name: &str) -> (Redacted<T>, String) {
    (Redacted::new(), field_name.to_string())
}

const DEFAULT_CREDENTIAL_PATTERNS: &[&str] =
    &["token", "secret", "password", "api_key", "private_key"];

/// Prohibited data categories that must never appear in platform logs.
///
/// These categories correspond to the source-side allowlist defined in
/// ADR-0009 Section "Structured Log Contract".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProhibitedCategory {
    Credential,
    Command,
    RequestBody,
    ResponseBody,
    FileContent,
    Url,
    QueryString,
    HostPath,
    WorkspacePath,
    IpAddress,
    PortNumber,
    DependencyError,
    GuestOutput,
    EnvironmentValue,
}

impl ProhibitedCategory {
    pub const fn field_name(self) -> &'static str {
        match self {
            Self::Credential => "credential",
            Self::Command => "command",
            Self::RequestBody => "request_body",
            Self::ResponseBody => "response_body",
            Self::FileContent => "file_content",
            Self::Url => "url",
            Self::QueryString => "query_string",
            Self::HostPath => "host_path",
            Self::WorkspacePath => "workspace_path",
            Self::IpAddress => "ip_address",
            Self::PortNumber => "port_number",
            Self::DependencyError => "dependency_error",
            Self::GuestOutput => "guest_output",
            Self::EnvironmentValue => "environment_value",
        }
    }

    /// Checks whether a string contains patterns suggestive of the given prohibited
    /// category, using defaults for credential patterns. This is a conservative
    /// heuristic, not a security boundary.
    #[must_use]
    pub fn is_suspected_in(self, value: &str) -> bool {
        self.is_suspected_with_patterns(value, DEFAULT_CREDENTIAL_PATTERNS)
    }

    /// Like [`is_suspected_in`] but with configurable credential redaction patterns.
    #[must_use]
    pub fn is_suspected_with_patterns(self, value: &str, credential_patterns: &[&str]) -> bool {
        match self {
            Self::HostPath | Self::WorkspacePath => {
                value.starts_with('/') || value.starts_with("\\\\")
            }
            Self::Credential => {
                let lower = value.to_lowercase();
                credential_patterns.iter().any(|p| lower.contains(p))
            }
            // Command-like patterns are low-confidence; checks for paths or known binary patterns
            // to reduce false positives on multi-word safe text.
            Self::Command => value.contains('/') || value.contains("\\") || value.contains(".exe"),
            Self::EnvironmentValue => value.contains('='),
            Self::IpAddress => value.parse::<std::net::IpAddr>().is_ok(),
            Self::Url => value.starts_with("http://") || value.starts_with("https://"),
            Self::QueryString => value.contains('?') && value.contains('='),
            Self::GuestOutput
            | Self::RequestBody
            | Self::ResponseBody
            | Self::FileContent
            | Self::DependencyError => false,
            Self::PortNumber => value.parse::<u16>().is_ok(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Redacted tests ──

    #[test]
    fn redacted_serializes_with_flag() {
        let r: Redacted<String> = Redacted::new();
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(json, r#"{"redacted":true}"#);
    }

    #[test]
    fn redacted_field_name_tracking() {
        let (_redacted, field_name) = redact("secret_value", "auth_token");
        assert_eq!(field_name, "auth_token");
    }

    #[test]
    fn redacted_is_clone_and_eq() {
        let r1: Redacted<u64> = Redacted::new();
        let r2 = r1.clone();
        assert_eq!(r1, r2);
    }

    // ── LogSeverity tests ──

    #[test]
    fn severity_numbers_match_otel_spec() {
        assert_eq!(LogSeverity::Trace.severity_number(), 1);
        assert_eq!(LogSeverity::Debug.severity_number(), 5);
        assert_eq!(LogSeverity::Info.severity_number(), 9);
        assert_eq!(LogSeverity::Warn.severity_number(), 13);
        assert_eq!(LogSeverity::Error.severity_number(), 17);
    }

    #[test]
    fn severity_serializes_uppercase() {
        assert_eq!(
            serde_json::to_string(&LogSeverity::Error).unwrap(),
            r#""ERROR""#
        );
        assert_eq!(
            serde_json::to_string(&LogSeverity::Warn).unwrap(),
            r#""WARN""#
        );
        assert_eq!(
            serde_json::to_string(&LogSeverity::Info).unwrap(),
            r#""INFO""#
        );
        assert_eq!(
            serde_json::to_string(&LogSeverity::Debug).unwrap(),
            r#""DEBUG""#
        );
        assert_eq!(
            serde_json::to_string(&LogSeverity::Trace).unwrap(),
            r#""TRACE""#
        );
    }

    // ── LogRecordBuilder / LogRecord tests ──

    fn make_error_record() -> LogRecord {
        LogRecordBuilder::new(
            "pico-host-agent",
            "boot_not_ready",
            "sandbox boot did not become ready",
        )
        .severity(LogSeverity::Error)
        .sandbox_id("sbx_01abc")
        .operation_id("opr_01def")
        .host_id("host-1")
        .cell_id("cell-a")
        .region("us-east-1")
        .outcome("protocol_error")
        .reason("protocol")
        .lifecycle_state("Failed")
        .backend("firecracker")
        .component("host-agent")
        .build()
    }

    #[test]
    fn log_record_contains_all_canonical_fields() {
        let record = make_error_record();
        let json = record.to_json();

        assert!(json.contains(r#""event":"boot_not_ready""#));
        assert!(json.contains(r#""severity":"ERROR""#));
        assert!(json.contains(r#""sandbox_id":"sbx_01abc""#));
        assert!(json.contains(r#""operation_id":"opr_01def""#));
        assert!(json.contains(r#""host_id":"host-1""#));
        assert!(json.contains(r#""cell_id":"cell-a""#));
        assert!(json.contains(r#""region":"us-east-1""#));
        assert!(json.contains(r#""outcome":"protocol_error""#));
        assert!(json.contains(r#""reason":"protocol""#));
        assert!(json.contains(r#""lifecycle_state":"Failed""#));
        assert!(json.contains(r#""backend":"firecracker""#));
        assert!(json.contains(r#""service.name":"pico-host-agent""#));
    }

    #[test]
    fn optional_fields_are_omitted_when_none() {
        let record = LogRecordBuilder::new("test-svc", "test_event", "test message").build();
        let json = record.to_json();
        assert!(!json.contains("tenant_id"));
        assert!(!json.contains("request_id"));
        assert!(!json.contains("trace_id"));
        assert!(!json.contains("span_id"));
        assert!(!json.contains("phase"));
        assert!(!json.contains("source_location"));
    }

    #[test]
    fn redacted_fields_appear_in_payload() {
        let record = LogRecordBuilder::new("test-svc", "test_event", "test message")
            .severity(LogSeverity::Warn)
            .with_redacted_fields(vec!["command".into(), "host_path".into()])
            .build();
        let json = record.to_json();
        assert!(json.contains(r#""redacted":true"#));
        assert!(json.contains(r#""redacted_fields":["command","host_path"]"#));
    }

    #[test]
    fn redacted_fields_defaults_to_empty_and_redacted_false() {
        let record = LogRecordBuilder::new("test-svc", "test_event", "test message").build();
        assert!(!record.redacted);
        assert!(record.redacted_fields.is_empty());
    }

    #[test]
    fn builder_sets_all_correlation_ids() {
        let record = LogRecordBuilder::new("test-svc", "test_event", "test message")
            .tenant_id("tnt_01")
            .request_id("req_01")
            .trace_id("abc123")
            .span_id("span456")
            .operation_id("opr_01")
            .build();
        let json = record.to_json();
        assert!(json.contains(r#""tenant_id":"tnt_01""#));
        assert!(json.contains(r#""request_id":"req_01""#));
        assert!(json.contains(r#""trace_id":"abc123""#));
        assert!(json.contains(r#""span_id":"span456""#));
        assert!(json.contains(r#""operation_id":"opr_01""#));
    }

    #[test]
    fn lifecycle_operation_sets_canonical_label() {
        let record = LogRecordBuilder::new("test-svc", "test_event", "test message")
            .operation(LifecycleOperation::Boot)
            .build();
        let json = record.to_json();
        assert!(json.contains(r#""operation":"boot""#));
    }

    // ── Negative tests: prohibited categories ──

    #[test]
    fn credential_like_strings_are_suspected() {
        assert!(ProhibitedCategory::Credential.is_suspected_in("auth_token=abc"));
        assert!(ProhibitedCategory::Credential.is_suspected_in("my_secret_key"));
        assert!(ProhibitedCategory::Credential.is_suspected_in("api_key_123"));
        assert!(ProhibitedCategory::Credential.is_suspected_in("the_password_is_xyz"));
        assert!(ProhibitedCategory::Credential.is_suspected_in("my_private_key"));
    }

    #[test]
    fn path_like_strings_are_suspected() {
        assert!(ProhibitedCategory::HostPath.is_suspected_in("/etc/pico/config"));
        assert!(ProhibitedCategory::HostPath.is_suspected_in("/var/lib/pico/workspaces"));
        assert!(
            ProhibitedCategory::WorkspacePath.is_suspected_in("/var/lib/pico/workspaces/sbx_01")
        );
    }

    #[test]
    fn url_like_strings_are_suspected() {
        assert!(ProhibitedCategory::Url.is_suspected_in("https://example.com/api"));
        assert!(ProhibitedCategory::Url.is_suspected_in("http://localhost:8080"));
    }

    #[test]
    fn ip_address_strings_are_suspected() {
        assert!(ProhibitedCategory::IpAddress.is_suspected_in("192.168.1.1"));
        assert!(ProhibitedCategory::IpAddress.is_suspected_in("::1"));
        assert!(ProhibitedCategory::IpAddress.is_suspected_in("10.0.0.1"));
    }

    #[test]
    fn safe_labels_are_not_suspected() {
        assert!(!ProhibitedCategory::Credential.is_suspected_in("success"));
        assert!(!ProhibitedCategory::HostPath.is_suspected_in("boot_not_ready"));
        assert!(!ProhibitedCategory::Url.is_suspected_in("internal_error"));
        assert!(!ProhibitedCategory::IpAddress.is_suspected_in("guest_not_ready"));
    }

    #[test]
    fn port_number_strings_are_suspected() {
        assert!(ProhibitedCategory::PortNumber.is_suspected_in("8080"));
        assert!(ProhibitedCategory::PortNumber.is_suspected_in("22"));
    }

    #[test]
    fn non_port_numbers_are_not_suspected() {
        assert!(!ProhibitedCategory::PortNumber.is_suspected_in("not_a_port"));
        assert!(!ProhibitedCategory::PortNumber.is_suspected_in("65536"));
    }

    // ── Round-trip: error record has all required fields per ADR-0009 ──

    #[test]
    fn error_record_satisfies_operation_terminal_contract() {
        let record = make_error_record();

        assert_eq!(record.severity, LogSeverity::Error);
        assert!(record.sandbox_id.is_some());
        assert!(record.operation_id.is_some());
        assert!(record.host_id.is_some());
        assert!(record.cell_id.is_some());
        assert!(record.region.is_some());
        assert!(record.outcome.is_some());
        assert!(record.reason.is_some());
        assert!(record.lifecycle_state.is_some());
        assert!(record.backend.is_some());

        assert_eq!(record.service_name, "pico-host-agent");
        assert_eq!(record.event, "boot_not_ready");
    }

    #[test]
    fn timestamp_is_iso8601_with_millis() {
        let record = LogRecordBuilder::new("test-svc", "test_event", "test message").build();
        assert!(record.timestamp.contains('T'));
        assert!(record.timestamp.contains(':'));
        assert!(
            record.timestamp.ends_with('Z')
                || record.timestamp.contains('+')
                || record.timestamp.contains('-')
        );
    }

    #[test]
    fn emit_does_not_panic_for_any_severity() {
        for severity in [
            LogSeverity::Trace,
            LogSeverity::Debug,
            LogSeverity::Info,
            LogSeverity::Warn,
            LogSeverity::Error,
        ] {
            let record = LogRecordBuilder::new("test-svc", "test_event", "test message")
                .severity(severity)
                .build();
            record.emit();
        }
    }
}

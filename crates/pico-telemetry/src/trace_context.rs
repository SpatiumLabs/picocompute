//! W3C Trace Context propagation helpers.
//!
//! Parses and injects `traceparent` / `tracestate` headers for distributed
//! tracing across service boundaries.  Also provides helpers for mapping
//! lifecycle outcome codes to OpenTelemetry span status and for recording
//! bounded, tenant-safe attributes on the current tracing span.

use hashbrown::HashMap;
use opentelemetry::trace::{SpanContext, SpanId, TraceContextExt, TraceFlags, TraceId, TraceState};

use crate::lifecycle::LifecycleOutcome;

// ── Header constants ──────────────────────────────────────────────

const TRACEPARENT_HEADER: &str = "traceparent";
const TRACESTATE_HEADER: &str = "tracestate";
const TRACEPARENT_VERSION: &str = "00";

// ── Parsed trace context ──────────────────────────────────────────

/// Extracted W3C trace context from a carrier (e.g. HTTP headers).
#[derive(Debug, Clone)]
pub struct ParsedTraceContext {
    pub trace_id: TraceId,
    pub span_id: SpanId,
    pub trace_flags: TraceFlags,
    pub trace_state: Option<String>,
}

/// Attempts to parse a W3C `traceparent` header from the given carrier.
///
/// Returns `None` if the header is absent, malformed, or has an
/// unsupported version.
pub fn extract_from_carrier(headers: &HashMap<String, String>) -> Option<ParsedTraceContext> {
    let header_value = headers.get(TRACEPARENT_HEADER)?;
    let parts: Vec<&str> = header_value.split('-').collect();
    if parts.len() != 4 || parts[0] != TRACEPARENT_VERSION {
        return None;
    }

    let trace_id = TraceId::from_hex(parts[1]).ok()?;
    let span_id = SpanId::from_hex(parts[2]).ok()?;
    let trace_flags_hex = u8::from_str_radix(parts[3], 16).ok()?;
    let trace_flags = TraceFlags::new(trace_flags_hex);
    let trace_state = headers.get(TRACESTATE_HEADER).cloned();

    Some(ParsedTraceContext {
        trace_id,
        span_id,
        trace_flags,
        trace_state,
    })
}

/// Injects the current OpenTelemetry span context into a carrier as a
/// `traceparent` header.  Does nothing when the current span is invalid or
/// disabled.
pub fn inject_into_carrier(carrier: &mut HashMap<String, String>) {
    let ctx = opentelemetry::Context::current();
    let span_ref = ctx.span();
    let span_ctx = span_ref.span_context();
    if !span_ctx.is_valid() {
        return;
    }

    let traceparent = format!(
        "{}-{}-{}-{:02x}",
        TRACEPARENT_VERSION,
        span_ctx.trace_id(),
        span_ctx.span_id(),
        span_ctx.trace_flags().to_u8(),
    );
    carrier.insert(TRACEPARENT_HEADER.to_string(), traceparent);
}

// ── Span helpers ──────────────────────────────────────────────────

/// Returns the hex-encoded trace ID of the currently active span, if any.
pub fn current_trace_id_hex() -> Option<String> {
    let ctx = opentelemetry::Context::current();
    let span_ref = ctx.span();
    let span_ctx = span_ref.span_context();
    if span_ctx.is_valid() {
        Some(span_ctx.trace_id().to_string())
    } else {
        None
    }
}

/// Returns the hex-encoded span ID of the currently active span, if any.
pub fn current_span_id_hex() -> Option<String> {
    let ctx = opentelemetry::Context::current();
    let span_ref = ctx.span();
    let span_ctx = span_ref.span_context();
    if span_ctx.is_valid() {
        Some(span_ctx.span_id().to_string())
    } else {
        None
    }
}

/// Returns the [`TraceFlags`] of the currently active span, if any.
pub fn current_trace_flags() -> Option<TraceFlags> {
    let ctx = opentelemetry::Context::current();
    let span_ref = ctx.span();
    let span_ctx = span_ref.span_context();
    span_ctx.is_valid().then_some(span_ctx.trace_flags())
}

/// Returns the `tracestate` header value of the currently active span, if any.
pub fn current_trace_state() -> Option<String> {
    let ctx = opentelemetry::Context::current();
    let span_ref = ctx.span();
    let span_ctx = span_ref.span_context();
    if !span_ctx.is_valid() {
        return None;
    }
    let raw = span_ctx.trace_state().header();
    (!raw.is_empty()).then_some(raw)
}

/// Parses a W3C `traceparent` / `tracestate` pair into a remote OpenTelemetry
/// parent [`Context`] suitable for `tracing_opentelemetry::OpenTelemetrySpanExt::set_parent`.
///
/// Returns `None` if `traceparent` is absent, malformed, or has an unsupported
/// version.
pub fn parent_context_from_carrier(
    traceparent: Option<&str>,
    tracestate: Option<&str>,
) -> Option<opentelemetry::Context> {
    let mut headers = HashMap::new();
    if let Some(tp) = traceparent {
        headers.insert(TRACEPARENT_HEADER.to_string(), tp.to_string());
    }
    if let Some(ts) = tracestate {
        headers.insert(TRACESTATE_HEADER.to_string(), ts.to_string());
    }

    let parsed = extract_from_carrier(&headers)?;

    let trace_state: TraceState = parsed
        .trace_state
        .as_deref()
        .and_then(|s| s.parse().ok())
        .unwrap_or_default();

    let span_context = SpanContext::new(
        parsed.trace_id,
        parsed.span_id,
        parsed.trace_flags,
        true, // is_remote
        trace_state,
    );

    Some(opentelemetry::Context::new().with_remote_span_context(span_context))
}

/// Sets the parent context on a tracing span from W3C trace headers.
///
/// This is a convenience function that combines [`parent_context_from_carrier`]
/// with `tracing_opentelemetry::OpenTelemetrySpanExt::set_parent`.
///
/// # Arguments
///
/// * `span` - The tracing span to set the parent on
/// * `traceparent` - Optional `traceparent` header value
/// * `tracestate` - Optional `tracestate` header value
///
/// # Example
///
/// ```rust,ignore
/// use pico_telemetry::trace_context::set_parent_from_trace_headers;
/// use tracing::info_span;
///
/// let span = info_span!("my_operation");
/// set_parent_from_trace_headers(&span, Some("00-..."), None);
/// ```
pub fn set_parent_from_trace_headers(
    span: &tracing::Span,
    traceparent: Option<&str>,
    tracestate: Option<&str>,
) {
    if let Some(parent_cx) = parent_context_from_carrier(traceparent, tracestate) {
        use tracing_opentelemetry::OpenTelemetrySpanExt;
        let _ = span.set_parent(parent_cx);
    }
}

// ── Lifecycle outcome → span status ───────────────────────────────

/// Maps a [`LifecycleOutcome`] to an `opentelemetry::trace::Status`.
pub fn outcome_to_otel_status(outcome: LifecycleOutcome) -> opentelemetry::trace::Status {
    match outcome {
        LifecycleOutcome::Success => opentelemetry::trace::Status::Ok,
        LifecycleOutcome::InternalError => opentelemetry::trace::Status::error("internal_error"),
        LifecycleOutcome::RuntimeFailed => opentelemetry::trace::Status::error("runtime_failed"),
        LifecycleOutcome::Timeout => opentelemetry::trace::Status::error("timeout"),
        LifecycleOutcome::Cancelled => opentelemetry::trace::Status::error("cancelled"),
        LifecycleOutcome::PolicyRejected => opentelemetry::trace::Status::error("policy_rejected"),
        LifecycleOutcome::QuotaRejected => opentelemetry::trace::Status::error("quota_rejected"),
        LifecycleOutcome::PlacementFailed => {
            opentelemetry::trace::Status::error("placement_failed")
        }
    }
}

// ── Bounded attribute keys ────────────────────────────────────────

/// Tenant-safe attribute keys allowed on lifecycle spans.
pub mod attr {
    pub const SANDBOX_ID: &str = "sandbox_id";
    pub const OPERATION_ID: &str = "operation_id";
    pub const TENANT_ID: &str = "tenant_id";
    pub const BACKEND: &str = "backend";
    pub const OPERATION: &str = "lifecycle_operation";
    pub const OUTCOME: &str = "outcome";
    pub const REASON: &str = "reason";
    pub const HOST_ID: &str = "host_id";
    pub const CELL_ID: &str = "cell_id";
    pub const REGION: &str = "region";
}

/// Records a bounded, tenant-safe attribute on the current tracing span.
///
/// # Panics (in debug)
///
/// Panics when `key` is not in the allowed attribute set so that
/// accidental leakage of tenant-supplied values is caught early.
pub fn record_bounded_attr(key: &str, value: &str) {
    debug_assert!(
        is_bounded_key(key),
        "attempted to record unbounded span attribute '{key}'; \
         only the keys defined in trace_context::attr are allowed"
    );
    tracing::Span::current().record(key, value);
}

/// Returns `true` when `key` is in the approved tenant-safe set.
#[must_use]
pub fn is_bounded_key(key: &str) -> bool {
    matches!(
        key,
        attr::SANDBOX_ID
            | attr::OPERATION_ID
            | attr::TENANT_ID
            | attr::BACKEND
            | attr::OPERATION
            | attr::OUTCOME
            | attr::REASON
            | attr::HOST_ID
            | attr::CELL_ID
            | attr::REGION
    )
}

/// Sets the OpenTelemetry span status on the current tracing span from a
/// [`LifecycleOutcome`] and optional reason string.
///
/// Uses `tracing_opentelemetry::OpenTelemetrySpanExt` to set the status.
pub fn set_span_status_from_outcome(outcome: LifecycleOutcome, reason: Option<&str>) {
    use tracing_opentelemetry::OpenTelemetrySpanExt;

    let mut status = outcome_to_otel_status(outcome);
    if let Some(r) = reason
        && !r.is_empty()
    {
        status = opentelemetry::trace::Status::error(format!("{}: {r}", outcome.as_str()));
    }

    tracing::Span::current().set_status(status);
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── traceparent parsing ──────────────────────────────────

    #[test]
    fn parse_valid_traceparent() {
        let mut headers = HashMap::new();
        headers.insert(
            "traceparent".into(),
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01".into(),
        );

        let ctx = extract_from_carrier(&headers).unwrap();
        assert_eq!(ctx.trace_id.to_string(), "0af7651916cd43dd8448eb211c80319c");
        assert_eq!(ctx.span_id.to_string(), "b7ad6b7169203331");
        assert!(ctx.trace_flags.is_sampled());
    }

    #[test]
    fn reject_unsupported_version() {
        let mut headers = HashMap::new();
        headers.insert(
            "traceparent".into(),
            "ff-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01".into(),
        );
        assert!(extract_from_carrier(&headers).is_none());
    }

    #[test]
    fn reject_malformed() {
        let mut headers = HashMap::new();
        headers.insert("traceparent".into(), "garbage".into());
        assert!(extract_from_carrier(&headers).is_none());
    }

    #[test]
    fn missing_header_returns_none() {
        let headers = HashMap::new();
        assert!(extract_from_carrier(&headers).is_none());
    }

    #[test]
    fn parse_with_tracestate() {
        let mut headers = HashMap::new();
        headers.insert(
            "traceparent".into(),
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01".into(),
        );
        headers.insert("tracestate".into(), "vendor=value".into());

        let ctx = extract_from_carrier(&headers).unwrap();
        assert_eq!(ctx.trace_state.as_deref(), Some("vendor=value"));
    }

    #[test]
    fn not_sampled_flag() {
        let mut headers = HashMap::new();
        headers.insert(
            "traceparent".into(),
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-00".into(),
        );
        let ctx = extract_from_carrier(&headers).unwrap();
        assert!(!ctx.trace_flags.is_sampled());
    }

    // ── parent_context_from_carrier ─────────────────────────────

    #[test]
    fn parent_context_builds_for_valid_traceparent() {
        let cx = parent_context_from_carrier(
            Some("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"),
            Some("vendor=value"),
        )
        .unwrap();
        let span_ref = cx.span();
        let span_ctx = span_ref.span_context();
        assert!(span_ctx.is_valid());
        assert_eq!(
            span_ctx.trace_id().to_string(),
            "0af7651916cd43dd8448eb211c80319c"
        );
        assert!(span_ctx.is_sampled());
    }

    #[test]
    fn parent_context_returns_none_without_traceparent() {
        assert!(parent_context_from_carrier(None, None).is_none());
    }

    #[test]
    fn parent_context_returns_none_for_malformed() {
        assert!(parent_context_from_carrier(Some("garbage"), None).is_none());
    }

    // ── outcome mapping ──────────────────────────────────────

    #[test]
    fn success_maps_to_ok() {
        let status = outcome_to_otel_status(LifecycleOutcome::Success);
        assert_eq!(status, opentelemetry::trace::Status::Ok);
    }

    #[test]
    fn failure_maps_to_error_with_reason() {
        for (outcome, expected) in [
            (LifecycleOutcome::InternalError, "internal_error"),
            (LifecycleOutcome::RuntimeFailed, "runtime_failed"),
            (LifecycleOutcome::Timeout, "timeout"),
            (LifecycleOutcome::Cancelled, "cancelled"),
            (LifecycleOutcome::PolicyRejected, "policy_rejected"),
            (LifecycleOutcome::QuotaRejected, "quota_rejected"),
            (LifecycleOutcome::PlacementFailed, "placement_failed"),
        ] {
            let status = outcome_to_otel_status(outcome);
            match status {
                opentelemetry::trace::Status::Error { description } => {
                    assert!(
                        description.contains(expected),
                        "expected '{expected}' in '{description}'"
                    );
                }
                _ => panic!("expected Status::Error for {expected}"),
            }
        }
    }

    // ── bounded keys ─────────────────────────────────────────

    #[test]
    fn all_defines_keys_are_bounded() {
        for key in [
            attr::SANDBOX_ID,
            attr::OPERATION_ID,
            attr::TENANT_ID,
            attr::BACKEND,
            attr::OPERATION,
            attr::OUTCOME,
            attr::REASON,
            attr::HOST_ID,
            attr::CELL_ID,
            attr::REGION,
        ] {
            assert!(is_bounded_key(key), "{key} should be bounded");
        }
    }

    #[test]
    fn unknown_keys_are_not_bounded() {
        assert!(!is_bounded_key("command"));
        assert!(!is_bounded_key("env"));
        assert!(!is_bounded_key("stdout"));
        assert!(!is_bounded_key("path"));
        assert!(!is_bounded_key("secret"));
    }
}

//! Request ID propagation and structured HTTP tracing.
//!
//! This middleware gives every HTTP request a stable `x-request-id` that is
//! available in logs and returned on the response. If a caller already provides
//! an `x-request-id`, PicoCompute preserves it so upstream systems can correlate
//! logs across service boundaries. Otherwise, the middleware generates a UUID.
//!
//! Each request is logged in a `request` tracing span with the request ID,
//! method, URI, user agent, and referer. `tower_http` also emits request and
//! response events at `INFO`, and classifies HTTP 5xx responses as failures.
//!
//! Incoming W3C `traceparent` and `tracestate` headers are extracted and
//! attached as the parent context for the request span so that distributed
//! traces propagate through the API surface.

use axum::extract::Request;
use axum::http::{
    HeaderName,
    header::{REFERER, USER_AGENT},
};
use tower::ServiceBuilder;
use tower::layer::util::{Identity, Stack};
use tower_http::classify::{ServerErrorsAsFailures, SharedClassifier};
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::trace::{DefaultOnRequest, DefaultOnResponse, TraceLayer};
use tracing::{Level, Span, info_span};

const REQUEST_ID_HEADER: &str = "x-request-id";

type RequestTraceLayer = TraceLayer<
    SharedClassifier<ServerErrorsAsFailures>,
    fn(&Request) -> Span,
    DefaultOnRequest,
    DefaultOnResponse,
>;

type RequestTracingLayer = ServiceBuilder<
    Stack<
        PropagateRequestIdLayer,
        Stack<RequestTraceLayer, Stack<SetRequestIdLayer<MakeRequestUuid>, Identity>>,
    >,
>;

/// Builds the request tracing layer used by the API router.
///
/// Layer ordering is intentional:
///
/// 1. `SetRequestIdLayer` preserves an inbound `x-request-id` or generates one.
/// 2. `TraceLayer` records the span after the request ID has been set.
/// 3. `PropagateRequestIdLayer` writes that same request ID onto the response.
pub(crate) fn request_tracing_layer() -> RequestTracingLayer {
    let request_id_header = HeaderName::from_static(REQUEST_ID_HEADER);

    ServiceBuilder::new()
        .layer(SetRequestIdLayer::new(
            request_id_header.clone(),
            MakeRequestUuid,
        ))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(make_request_span as fn(&Request) -> Span)
                .on_request(DefaultOnRequest::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
        .layer(PropagateRequestIdLayer::new(request_id_header))
}

/// Creates the per-request tracing span.
///
/// Invalid or missing text headers are represented as `-` so logging never
/// rejects a request. Missing request IDs should only happen if this function is
/// reused without `SetRequestIdLayer`, so the span records `unknown`.
///
/// Incoming W3C `traceparent` / `tracestate` headers are parsed and attached as
/// the parent context so distributed traces propagate across the API.
fn make_request_span(request: &Request) -> Span {
    let request_id = request
        .headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("unknown");

    let user_agent = request
        .headers()
        .get(USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("-")
        .to_owned();

    let referer = request
        .headers()
        .get(REFERER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("-")
        .to_owned();

    // Extract W3C trace context from headers for distributed tracing.
    let traceparent = request
        .headers()
        .get("traceparent")
        .and_then(|v| v.to_str().ok());
    let tracestate = request
        .headers()
        .get("tracestate")
        .and_then(|v| v.to_str().ok());

    let span = info_span!(
        "request",
        request_id = %request_id,
        method = %request.method(),
        uri = %request.uri(),
        user_agent = %user_agent,
        referer = %referer,
    );

    pico_telemetry::trace_context::set_parent_from_trace_headers(&span, traceparent, tracestate);

    span
}

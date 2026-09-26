//! OpenTelemetry tracing layer.

use opentelemetry::{KeyValue, trace::TracerProvider as _};
use opentelemetry_otlp::WithExportConfig as _;
use opentelemetry_sdk::{
    Resource,
    trace::{Sampler, SdkTracerProvider},
};
use parking_lot::Mutex;
use std::sync::LazyLock;
use tracing_opentelemetry::OpenTelemetryLayer;

use crate::BoxError;
use crate::settings::TracingSettings;

static TRACER_PROVIDER: LazyLock<Mutex<Option<SdkTracerProvider>>> =
    LazyLock::new(|| Mutex::new(None));

pub(crate) fn init_layer(
    settings: &TracingSettings,
    service_name: &str,
) -> Result<
    Option<OpenTelemetryLayer<tracing_subscriber::Registry, opentelemetry_sdk::trace::Tracer>>,
    BoxError,
> {
    if settings.otlp_endpoint.is_empty() {
        return Ok(None);
    }

    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(&settings.otlp_endpoint)
        .build()
        .map_err(|e| Box::new(e) as BoxError)?;

    let resource = Resource::builder()
        .with_attributes(vec![KeyValue::new(
            "service.name",
            service_name.to_string(),
        )])
        .build();

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resource)
        .with_sampler(Sampler::TraceIdRatioBased(settings.sample_rate))
        .build();

    let tracer = provider.tracer("pico");
    let layer = OpenTelemetryLayer::new(tracer);

    let mut guard = TRACER_PROVIDER.lock();
    *guard = Some(provider);

    Ok(Some(layer))
}

pub(crate) fn shutdown_tracing() {
    if let Some(provider) = TRACER_PROVIDER.lock().take() {
        let _ = provider.shutdown();
    }
}

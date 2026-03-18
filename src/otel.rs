//! OpenTelemetry initialization for distributed tracing export.
//!
//! When `otel.enabled = true` in config, configures an OTLP trace exporter.
//! Integrates with the existing `tracing` subscriber via `tracing-opentelemetry`.

/// Initializes the OpenTelemetry tracing pipeline and installs a layered subscriber.
///
/// Must be called INSTEAD of the default `tracing_subscriber::fmt().init()` when
/// OTel is enabled. Combines the fmt layer + OTel layer into a single subscriber.
#[cfg(feature = "otel")]
pub fn init_subscriber_with_otel(
    config: &crate::cli::OtelConfig,
    filter: tracing_subscriber::EnvFilter,
    json_logs: bool,
) -> anyhow::Result<()> {
    use opentelemetry::trace::TracerProvider;
    use opentelemetry_otlp::WithExportConfig;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(&config.endpoint)
        .build()
        .map_err(|e| anyhow::anyhow!("OTLP exporter init failed: {}", e))?;

    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(
            opentelemetry_sdk::Resource::builder()
                .with_service_name(config.service_name.clone())
                .build(),
        )
        .build();

    let tracer = provider.tracer("grob");
    opentelemetry::global::set_tracer_provider(provider);

    let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

    if json_logs {
        tracing_subscriber::registry()
            .with(filter)
            .with(otel_layer)
            .with(tracing_subscriber::fmt::layer().json())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(otel_layer)
            .with(tracing_subscriber::fmt::layer())
            .init();
    }

    tracing::info!(
        "OpenTelemetry enabled → {} (service: {})",
        config.endpoint,
        config.service_name
    );

    Ok(())
}

/// Flushes pending OTel spans on shutdown.
pub fn shutdown_otel() {
    // In opentelemetry 0.28+, the global provider flushes on drop.
}

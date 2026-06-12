//! OpenTelemetry initialization for distributed tracing and log export.
//!
//! When `otel.enabled = true` in config, configures an OTLP trace exporter and,
//! when `otel.logs = true`, an OTLP log exporter that mirrors `tracing` events
//! as the third OpenTelemetry signal. All transports are gRPC/tonic (no
//! reqwest/native-tls/openssl). Integrates with the existing `tracing`
//! subscriber via `tracing-opentelemetry` and `opentelemetry-appender-tracing`.

/// Process-lifetime handle to the OTLP log pipeline, kept so [`shutdown_otel`]
/// can flush the batch processor on exit (the global subscriber that also holds
/// a logger never drops).
#[cfg(feature = "otel")]
static LOGGER_PROVIDER: std::sync::OnceLock<opentelemetry_sdk::logs::SdkLoggerProvider> =
    std::sync::OnceLock::new();

/// Initializes the OpenTelemetry tracing pipeline and installs a layered subscriber.
///
/// Must be called INSTEAD of the default `tracing_subscriber::fmt().init()` when
/// OTel is enabled. Combines the fmt layer + OTel trace layer (+ optional OTLP
/// log bridge) into a single subscriber. The stdout fmt layer is always kept, so
/// enabling `logs` produces a DOUBLE output (stdout + OTLP).
///
/// # Errors
///
/// Returns an error if the OTLP trace or log exporter fails to build.
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
    use tracing_subscriber::Layer;

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

    // Optional OTLP log bridge: mirrors `tracing` events into OTLP logs. Its
    // own target filter drops the OTel SDK / gRPC transport events to avoid a
    // feedback loop (exporting a log emits more logs). The global `EnvFilter`
    // still applies, so RUST_LOG levels are honoured.
    let log_bridge = if config.logs {
        let log_exporter = opentelemetry_otlp::LogExporter::builder()
            .with_tonic()
            .with_endpoint(&config.endpoint)
            .build()
            .map_err(|e| anyhow::anyhow!("OTLP log exporter init failed: {}", e))?;

        let logger_provider = opentelemetry_sdk::logs::SdkLoggerProvider::builder()
            .with_batch_exporter(log_exporter)
            .with_resource(
                opentelemetry_sdk::Resource::builder()
                    .with_service_name(config.service_name.clone())
                    .build(),
            )
            .build();

        let bridge = opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(
            &logger_provider,
        );

        // Keep the provider alive for the process and reachable for shutdown
        // flush. The bridge holds its own logger clone, so moving it here is safe.
        let _ = LOGGER_PROVIDER.set(logger_provider);

        Some(
            bridge.with_filter(tracing_subscriber::filter::filter_fn(|meta| {
                let target = meta.target();
                !(target.starts_with("opentelemetry")
                    || target.starts_with("tonic")
                    || target.starts_with("h2")
                    || target.starts_with("hyper")
                    || target.starts_with("tower"))
            })),
        )
    } else {
        None
    };

    if json_logs {
        tracing_subscriber::registry()
            .with(filter)
            .with(otel_layer)
            .with(log_bridge)
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_timer(super::log_time::UtcTimer),
            )
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(otel_layer)
            .with(log_bridge)
            .with(tracing_subscriber::fmt::layer().with_timer(super::log_time::UtcTimer))
            .init();
    }

    tracing::info!(
        "OpenTelemetry enabled → {} (service: {})",
        config.endpoint,
        config.service_name
    );
    if config.logs {
        tracing::info!("OTLP logs export enabled → {}", config.endpoint);
    }

    Ok(())
}

/// Flushes pending OTel spans and logs on shutdown.
///
/// Spans flush on drop of the global provider (opentelemetry 0.28+). The OTLP
/// log batch processor is explicitly flushed via the retained
/// [`struct@LOGGER_PROVIDER`] so buffered logs are not lost on exit. Gated behind
/// `#[cfg(feature = "otel")]` so it is not compiled into non-otel builds.
#[cfg(feature = "otel")]
pub fn shutdown_otel() {
    if let Some(provider) = LOGGER_PROVIDER.get() {
        // Best-effort: exports any buffered logs, then stops the processor.
        let _ = provider.shutdown();
    }
}

/// No-op stub for non-otel builds — allows the call site in `start_server` to be
/// written unconditionally.
#[cfg(not(feature = "otel"))]
pub fn shutdown_otel() {}

#[cfg(all(test, feature = "otel"))]
mod tests {
    use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
    use opentelemetry_sdk::logs::SdkLoggerProvider;
    use tracing_subscriber::layer::SubscriberExt;

    // The OTLP log bridge must construct and accept `tracing` events as a layer.
    // Uses a no-exporter provider (no network/runtime needed); reaching the end
    // without panicking proves the bridge builds and its `on_event` path runs.
    #[test]
    fn otlp_log_bridge_constructs_and_handles_events() {
        let provider = SdkLoggerProvider::builder().build();
        let bridge = OpenTelemetryTracingBridge::new(&provider);

        let subscriber = tracing_subscriber::registry().with(bridge);
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(test = true, "otlp log bridge smoke test");
            tracing::warn!("second event through the bridge");
        });

        // Flush is a no-op without an exporter, but exercises the shutdown path.
        let _ = provider.force_flush();
    }
}

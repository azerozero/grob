//! OpenTelemetry metrics bridge — fans the existing `metrics` instrumentation
//! out to an OTLP `MeterProvider` without re-instrumenting any call site.
//!
//! Companion to [`super::otel`] (the trace side). Installed only under the
//! `otel` feature AND when `[otel] metrics = true`: the single global `metrics`
//! recorder is wrapped in a [`metrics_util::layers::Fanout`] of
//! `[PrometheusRecorder, OtelRecorder]`, so the ~65 `counter!` / `gauge!` /
//! `histogram!` call sites feed BOTH backends from one source. Standing up a
//! second [`opentelemetry::metrics::Meter`] in front of those call sites would
//! re-instrument and drift; the bridge is the single-source alternative.
//!
//! # Instrument mapping
//!
//! | `metrics`       | OpenTelemetry           | Notes                                   |
//! |-----------------|-------------------------|-----------------------------------------|
//! | counter         | `Counter<u64>`          | `increment` → `add`; `absolute` → delta |
//! | gauge           | `Gauge<f64>`            | `set` → `record`; ±tracked in an atomic |
//! | histogram       | `Histogram<f64>`        | `record` → `record`                     |
//!
//! `metrics` labels map to OTel `KeyValue` attributes. `# HELP` / `# TYPE`
//! descriptions registered via `describe_*` are reused as instrument
//! descriptions/units.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use metrics::{
    Counter, CounterFn, Gauge, GaugeFn, Histogram, HistogramFn, Key, KeyName, Metadata, Recorder,
    SharedString, Unit,
};
use opentelemetry::metrics::{
    Counter as OtelCounter, Gauge as OtelGauge, Histogram as OtelHistogram, Meter, MeterProvider,
};
use opentelemetry::KeyValue;
use opentelemetry_sdk::metrics::SdkMeterProvider;

/// Builds an [`OtelRecorder`] backed by an OTLP push pipeline.
///
/// Stands up an `SdkMeterProvider` whose `PeriodicReader` exports over OTLP/gRPC
/// every `config.metrics_interval_secs` to `config.endpoint`. The provider is
/// owned by the returned recorder, keeping the background export thread alive
/// for the process lifetime once the recorder is installed globally.
///
/// # Errors
///
/// Returns an error if the OTLP gRPC exporter cannot be constructed (e.g. an
/// invalid endpoint). A missing collector is NOT an error here — exports fail
/// silently per interval, exactly like the trace exporter.
pub(crate) fn build_recorder(config: &crate::cli::OtelConfig) -> anyhow::Result<OtelRecorder> {
    use opentelemetry_otlp::WithExportConfig;

    let exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_tonic()
        .with_endpoint(&config.endpoint)
        .build()
        .map_err(|e| anyhow::anyhow!("OTLP metric exporter init failed: {}", e))?;

    // A zero interval would make the reader fall back to its 60s default, so
    // clamp to at least 1s to honour an explicitly tiny configured value.
    let interval = std::time::Duration::from_secs(config.metrics_interval_secs.max(1));
    let reader = opentelemetry_sdk::metrics::PeriodicReader::builder(exporter)
        .with_interval(interval)
        .build();

    let provider = SdkMeterProvider::builder()
        .with_reader(reader)
        .with_resource(
            opentelemetry_sdk::Resource::builder()
                .with_service_name(config.service_name.clone())
                .build(),
        )
        .build();

    Ok(OtelRecorder::new(provider))
}

/// A [`metrics::Recorder`] that translates `metrics` call sites into OTel
/// instruments on a shared [`SdkMeterProvider`].
///
/// Cheap to clone — every field lives behind an [`Arc`], so a clone shares the
/// same provider, instrument caches, and handle state. Cloning before handing
/// one copy to the fan-out lets callers keep a probe for inspection (used in
/// tests via [`OtelRecorder::instrument_count`]).
#[derive(Clone)]
pub(crate) struct OtelRecorder {
    inner: Arc<Inner>,
}

struct Inner {
    // Owns the export pipeline; dropping it would stop the periodic reader.
    _provider: SdkMeterProvider,
    meter: Meter,
    // Instruments are cached by NAME so every label set shares one OTel stream
    // (creating duplicates for the same name degrades SDK performance).
    counter_instruments: DashMap<String, OtelCounter<u64>>,
    gauge_instruments: DashMap<String, OtelGauge<f64>>,
    histogram_instruments: DashMap<String, OtelHistogram<f64>>,
    // Handles are cached by full KEY (name + labels) so per-handle atomic state
    // (counter absolute baseline, gauge current value) persists across the
    // re-registration that the `metrics` macros perform on every emission.
    counter_handles: DashMap<Key, Arc<OtelCounterHandle>>,
    gauge_handles: DashMap<Key, Arc<OtelGaugeHandle>>,
    histogram_handles: DashMap<Key, Arc<OtelHistogramHandle>>,
    // `describe_*` metadata, keyed by name, applied when an instrument is built.
    descriptions: DashMap<String, Description>,
}

#[derive(Default, Clone)]
struct Description {
    unit: Option<String>,
    description: Option<String>,
}

impl OtelRecorder {
    /// Wraps an existing [`SdkMeterProvider`] as a `metrics` recorder.
    ///
    /// The provider is kept alive for the recorder's lifetime; callers building
    /// the OTLP pipeline should use [`build_recorder`] instead.
    pub(crate) fn new(provider: SdkMeterProvider) -> Self {
        let meter = provider.meter("grob");
        Self {
            inner: Arc::new(Inner {
                _provider: provider,
                meter,
                counter_instruments: DashMap::new(),
                gauge_instruments: DashMap::new(),
                histogram_instruments: DashMap::new(),
                counter_handles: DashMap::new(),
                gauge_handles: DashMap::new(),
                histogram_handles: DashMap::new(),
                descriptions: DashMap::new(),
            }),
        }
    }

    /// Returns the number of distinct OTel instruments created so far.
    ///
    /// Test-only probe proving the fan-out routed call sites into the bridge.
    #[cfg(test)]
    pub(crate) fn instrument_count(&self) -> usize {
        self.inner.counter_instruments.len()
            + self.inner.gauge_instruments.len()
            + self.inner.histogram_instruments.len()
    }
}

impl Inner {
    /// Gets or builds the OTel `Counter<u64>` for `name`, applying any
    /// registered description/unit on first creation.
    fn counter_instrument(&self, name: &str) -> OtelCounter<u64> {
        if let Some(inst) = self.counter_instruments.get(name) {
            return inst.clone();
        }
        let mut builder = self.meter.u64_counter(name.to_string());
        if let Some(desc) = self.descriptions.get(name) {
            if let Some(d) = &desc.description {
                builder = builder.with_description(d.clone());
            }
            if let Some(u) = &desc.unit {
                builder = builder.with_unit(u.clone());
            }
        } else if let Some(u) = infer_unit(name) {
            builder = builder.with_unit(u);
        }
        self.counter_instruments
            .entry(name.to_string())
            .or_insert_with(|| builder.build())
            .clone()
    }

    fn gauge_instrument(&self, name: &str) -> OtelGauge<f64> {
        if let Some(inst) = self.gauge_instruments.get(name) {
            return inst.clone();
        }
        let mut builder = self.meter.f64_gauge(name.to_string());
        if let Some(desc) = self.descriptions.get(name) {
            if let Some(d) = &desc.description {
                builder = builder.with_description(d.clone());
            }
            if let Some(u) = &desc.unit {
                builder = builder.with_unit(u.clone());
            }
        } else if let Some(u) = infer_unit(name) {
            builder = builder.with_unit(u);
        }
        self.gauge_instruments
            .entry(name.to_string())
            .or_insert_with(|| builder.build())
            .clone()
    }

    fn histogram_instrument(&self, name: &str) -> OtelHistogram<f64> {
        if let Some(inst) = self.histogram_instruments.get(name) {
            return inst.clone();
        }
        let mut builder = self.meter.f64_histogram(name.to_string());
        if let Some(desc) = self.descriptions.get(name) {
            if let Some(d) = &desc.description {
                builder = builder.with_description(d.clone());
            }
            if let Some(u) = &desc.unit {
                builder = builder.with_unit(u.clone());
            }
        } else if let Some(u) = infer_unit(name) {
            builder = builder.with_unit(u);
        }
        self.histogram_instruments
            .entry(name.to_string())
            .or_insert_with(|| builder.build())
            .clone()
    }
}

/// Maps `metrics` labels to OTel attributes.
fn attributes(key: &Key) -> Vec<KeyValue> {
    key.labels()
        .map(|l| KeyValue::new(l.key().to_string(), l.value().to_string()))
        .collect()
}

/// Infers an OTel unit from a metric-name suffix when none was registered.
///
/// grob's `describe_*` calls omit units, so this recovers the conventional
/// UCUM unit for time-based families. Returns `None` for unitless families
/// (counts, currency) so the exporter stays silent rather than guessing.
fn infer_unit(name: &str) -> Option<&'static str> {
    if name.ends_with("_seconds") {
        Some("s")
    } else if name.ends_with("_ms") {
        Some("ms")
    } else {
        None
    }
}

impl Recorder for OtelRecorder {
    fn describe_counter(&self, key: KeyName, unit: Option<Unit>, description: SharedString) {
        self.inner
            .descriptions
            .insert(key.as_str().to_string(), to_description(unit, description));
    }

    fn describe_gauge(&self, key: KeyName, unit: Option<Unit>, description: SharedString) {
        self.inner
            .descriptions
            .insert(key.as_str().to_string(), to_description(unit, description));
    }

    fn describe_histogram(&self, key: KeyName, unit: Option<Unit>, description: SharedString) {
        self.inner
            .descriptions
            .insert(key.as_str().to_string(), to_description(unit, description));
    }

    fn register_counter(&self, key: &Key, _metadata: &Metadata<'_>) -> Counter {
        if let Some(handle) = self.inner.counter_handles.get(key) {
            return Counter::from_arc(handle.clone());
        }
        let inst = self.inner.counter_instrument(key.name());
        let handle = Arc::new(OtelCounterHandle {
            inst,
            attrs: attributes(key),
            last_absolute: AtomicU64::new(0),
        });
        let handle = self
            .inner
            .counter_handles
            .entry(key.clone())
            .or_insert(handle)
            .clone();
        Counter::from_arc(handle)
    }

    fn register_gauge(&self, key: &Key, _metadata: &Metadata<'_>) -> Gauge {
        if let Some(handle) = self.inner.gauge_handles.get(key) {
            return Gauge::from_arc(handle.clone());
        }
        let inst = self.inner.gauge_instrument(key.name());
        let handle = Arc::new(OtelGaugeHandle {
            inst,
            attrs: attributes(key),
            current: AtomicU64::new(0),
        });
        let handle = self
            .inner
            .gauge_handles
            .entry(key.clone())
            .or_insert(handle)
            .clone();
        Gauge::from_arc(handle)
    }

    fn register_histogram(&self, key: &Key, _metadata: &Metadata<'_>) -> Histogram {
        if let Some(handle) = self.inner.histogram_handles.get(key) {
            return Histogram::from_arc(handle.clone());
        }
        let inst = self.inner.histogram_instrument(key.name());
        let handle = Arc::new(OtelHistogramHandle {
            inst,
            attrs: attributes(key),
        });
        let handle = self
            .inner
            .histogram_handles
            .entry(key.clone())
            .or_insert(handle)
            .clone();
        Histogram::from_arc(handle)
    }
}

fn to_description(unit: Option<Unit>, description: SharedString) -> Description {
    Description {
        unit: unit.map(|u| u.as_canonical_label().to_string()),
        description: if description.is_empty() {
            None
        } else {
            Some(description.to_string())
        },
    }
}

/// Per-(name+labels) counter handle bridging to an OTel additive counter.
struct OtelCounterHandle {
    inst: OtelCounter<u64>,
    attrs: Vec<KeyValue>,
    last_absolute: AtomicU64,
}

impl CounterFn for OtelCounterHandle {
    fn increment(&self, value: u64) {
        self.inst.add(value, &self.attrs);
    }

    fn absolute(&self, value: u64) {
        // OTel counters are additive-only, so translate an absolute reading into
        // the positive delta since the last one. grob never calls `absolute`
        // today; this keeps the bridge correct if a future call site does.
        let prev = self.last_absolute.swap(value, Ordering::Relaxed);
        if let Some(delta) = value.checked_sub(prev) {
            if delta > 0 {
                self.inst.add(delta, &self.attrs);
            }
        }
    }
}

/// Per-(name+labels) gauge handle bridging to an OTel last-value gauge.
struct OtelGaugeHandle {
    inst: OtelGauge<f64>,
    attrs: Vec<KeyValue>,
    // Current value as f64 bits, so `increment`/`decrement` can record the
    // running total (an OTel gauge only records absolute values).
    current: AtomicU64,
}

impl OtelGaugeHandle {
    /// Atomically applies `f` to the running value and returns the new value.
    fn update(&self, f: impl Fn(f64) -> f64) -> f64 {
        let mut prev = self.current.load(Ordering::Relaxed);
        loop {
            let next = f(f64::from_bits(prev));
            match self.current.compare_exchange_weak(
                prev,
                next.to_bits(),
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return next,
                Err(observed) => prev = observed,
            }
        }
    }
}

impl GaugeFn for OtelGaugeHandle {
    fn increment(&self, value: f64) {
        let next = self.update(|c| c + value);
        self.inst.record(next, &self.attrs);
    }

    fn decrement(&self, value: f64) {
        let next = self.update(|c| c - value);
        self.inst.record(next, &self.attrs);
    }

    fn set(&self, value: f64) {
        self.current.store(value.to_bits(), Ordering::Relaxed);
        self.inst.record(value, &self.attrs);
    }
}

/// Per-(name+labels) histogram handle bridging to an OTel histogram.
struct OtelHistogramHandle {
    inst: OtelHistogram<f64>,
    attrs: Vec<KeyValue>,
}

impl HistogramFn for OtelHistogramHandle {
    fn record(&self, value: f64) {
        self.inst.record(value, &self.attrs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn infer_unit_maps_time_suffixes_only() {
        assert_eq!(infer_unit("grob_request_duration_seconds"), Some("s"));
        assert_eq!(infer_unit("grob_provider_latency_ewma_ms"), Some("ms"));
        assert_eq!(infer_unit("grob_requests_total"), None);
        assert_eq!(infer_unit("grob_spend_usd"), None);
    }

    #[test]
    fn bridges_all_three_instrument_kinds() {
        // No reader: the provider aggregates without exporting, so the test
        // needs no tokio runtime or collector — we only assert the bridge
        // creates instruments and records without panicking.
        let provider = SdkMeterProvider::builder().build();
        let recorder = OtelRecorder::new(provider);

        let counter = recorder.register_counter(
            &Key::from_parts(
                "grob_requests_total",
                vec![metrics::Label::new("model", "x")],
            ),
            &metrics::Metadata::new("test", metrics::Level::INFO, None),
        );
        counter.increment(3);

        let gauge = recorder.register_gauge(
            &Key::from_name("grob_active_requests"),
            &metrics::Metadata::new("test", metrics::Level::INFO, None),
        );
        gauge.set(7.0);
        gauge.increment(1.0);
        gauge.decrement(2.0);

        let histogram = recorder.register_histogram(
            &Key::from_name("grob_request_duration_seconds"),
            &metrics::Metadata::new("test", metrics::Level::INFO, None),
        );
        histogram.record(0.25);

        assert_eq!(recorder.instrument_count(), 3);
    }

    #[test]
    fn caches_handles_by_key() {
        let provider = SdkMeterProvider::builder().build();
        let recorder = OtelRecorder::new(provider);
        let key = Key::from_name("grob_active_requests");
        let meta = metrics::Metadata::new("test", metrics::Level::INFO, None);

        // Same key registered twice must share one instrument (one OTel stream).
        let _g1 = recorder.register_gauge(&key, &meta);
        let _g2 = recorder.register_gauge(&key, &meta);
        assert_eq!(recorder.inner.gauge_instruments.len(), 1);
        assert_eq!(recorder.inner.gauge_handles.len(), 1);
    }
}

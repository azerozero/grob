# OTLP Exemplars (latency → trace correlation)

This document explains why grob does **not yet** emit OpenTelemetry exemplars on
its OTLP histograms, what the code already does in preparation, and exactly what
is needed to finish the feature.

## What exemplars are for

An *exemplar* is a sample attached to a histogram bucket that carries the
`trace_id`/`span_id` of a representative request. With exemplars, Grafana can
turn "this latency bucket spiked" into "open the trace that produced it" — the
`grob_request_duration_seconds_bucket` series gains clickable trace links
(Prometheus `query_exemplars`, Tempo/LGTM "trace to logs/metrics").

## Current status: exemplars are empty

`query_exemplars` on `grob_request_duration_seconds_bucket` returns nothing. This
is **not** a misconfiguration of grob — it is a hard limitation of the pinned
OpenTelemetry SDK.

## Root cause: `opentelemetry_sdk` 0.28 does not implement exemplars

grob is pinned to the `opentelemetry*` 0.28 release train (kept deliberately to
stay on a pure-rustls/tonic tree with no openssl). In `opentelemetry_sdk`
**0.28.0**:

- The data model carries the field — `metrics::data::Exemplar<T>` exists with
  `trace_id: [u8; 16]` / `span_id: [u8; 8]` — so the OTLP proto *can* represent
  exemplars.
- But the aggregation pipeline never populates it. Every aggregator
  (`internal/histogram.rs`, `sum.rs`, `last_value.rs`,
  `exponential_histogram.rs`, `aggregate.rs`) hardcodes `exemplars: vec![]` when
  it builds a data point, and **never reads the OTel `Context`** during `record`.
- There is **no public API to enable a reservoir**: `MeterProviderBuilder` only
  exposes `with_resource` / `with_reader` / `with_periodic_exporter` /
  `with_view`. There is no `with_exemplar_filter`, no `ExemplarFilter`, no
  `ExemplarReservoir`, no `TraceBased` type, and no `OTEL_METRICS_EXEMPLAR_FILTER`
  handling anywhere in the crate.

Consequently, **no change on grob's side can produce exemplars on 0.28** — not a
config flag, not a `Context` attach, not a custom `View`. The SDK simply does not
capture them.

Trace-based exemplar reservoirs landed in the SDK **after** 0.28 (the
`with_exemplar_filter(ExemplarFilter::TraceBased)` API and the reservoir
implementation appear in the ≥ 0.30 line).

## What grob already does (the half it can do today)

Even when the SDK gains exemplar support, a reservoir can only capture a
`trace_id` if the **OTel `Context` is current at the moment of `record`**.
`tracing-opentelemetry` stores each request's OTel span in the *tracing* span's
extensions but does **not** push it onto the OTel thread-local `Context`. So at
the metrics call-site, `opentelemetry::Context::current()` is empty.

`server::budget::record_request_metrics` therefore attaches the active span's
OTel context for the duration of the metric recording (feature-gated `otel`):

```rust
let cx = tracing::Span::current().context();          // OpenTelemetrySpanExt
if cx.span().span_context().is_valid() {
    let _guard = cx.attach();                          // OTel Context = request span
    // counter!/histogram!/… record here
}
```

The request span itself comes from the `tower_http` `TraceLayer` (`http_request`
span), which `tracing-opentelemetry` exports as an OTel span under the `otel`
feature. The attach is a **no-op for exemplars on 0.28** (the SDK ignores the
Context), and it is also a no-op when `otel` is disabled or no span is active
(the validity guard). It exists so that the day the SDK is upgraded, exemplars
work without further dispatch-pipeline changes.

## What is needed to finish it

1. **Upgrade the OTel stack** from 0.28 to ≥ 0.30 across all crates:
   `opentelemetry`, `opentelemetry_sdk`, `opentelemetry-otlp`,
   `opentelemetry-appender-tracing`, `tracing-opentelemetry`. This is a major,
   breaking bump that touches `src/shared/otel.rs` (traces + logs) and
   `src/shared/otel_metrics.rs` (the metrics→OTel bridge). It must preserve the
   rustls/tonic-only tree (no openssl/native-tls regression).
2. **Enable a trace-based reservoir** on the bridge's `SdkMeterProvider`:
   `builder.with_exemplar_filter(ExemplarFilter::TraceBased)` (exact name per the
   target version).
3. **Keep the `Context` attach** above (already in place).
4. **Verify empirically**: run grob with `[otel] metrics = true` against a
   collector, generate traffic, then
   `query_exemplars(grob_request_duration_seconds_bucket)` must return points
   carrying a non-empty `trace_id` label.

Until step 1+2 land, exemplars remain empty by SDK design, and that is expected.

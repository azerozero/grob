# grob — Grafana dashboard

`grob-overview.json` is a ready-to-import Grafana dashboard for grob, driven by
the Prometheus metrics grob exposes (always-on `/metrics`) and/or the OTLP
metrics export (`[otel] metrics = true`, `otel` build feature). It charts
request rate by model and by provider (so provider fallback is visible),
latency p50/p95/p99 (from the `grob_request_duration_seconds` histogram),
outcomes by status, provider errors, token throughput, and spend vs. budget.

## Try it locally against the LGTM stack

[`grafana/otel-lgtm`](https://github.com/grafana/docker-otel-lgtm) bundles
Grafana + Prometheus + Tempo + Loki + an OpenTelemetry Collector in one image.

```sh
# Any container runtime works (docker, podman, ...).
podman run -d --name lgtm -p 3000:3000 -p 4317:4317 -p 4318:4318 \
  docker.io/grafana/otel-lgtm
```

Point grob at the collector (OTLP gRPC on :4317) — build with the `otel`
feature and add to your config:

```toml
[otel]
enabled = true                 # traces -> Tempo
endpoint = "http://localhost:4317"
service_name = "grob"
metrics = true                 # metrics -> Prometheus (fan-out, also keeps /metrics)
metrics_interval_secs = 5
```

```sh
cargo run --features otel -- run
```

Then open Grafana at <http://localhost:3000> (admin / admin) and import
`grob-overview.json` (Dashboards → New → Import). Traces land in the Tempo
datasource (search `service.name = grob`).

## In Kubernetes

The Helm chart (`deploy/helm/grob`) ships a `ServiceMonitor` (Prometheus
Operator) that scrapes `/metrics`. Import this dashboard into your Grafana, or
add it to a dashboard ConfigMap consumed by the Grafana sidecar.

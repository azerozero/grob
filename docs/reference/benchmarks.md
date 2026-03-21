# Benchmarks

> **90 µs overhead** with routing + auth + rate limiting + cache + DLP on 4 vCPU ARM — 40x faster than LiteLLM, with more features than Bifrost.

Grob v0.24.1 — 2026-03-21 — `grob bench --concurrent` (c=vCPU, 5 sec/scenario, mock TCP backend on localhost).

## Proxy overhead vs competitors

Overhead = P50 proxy − P50 direct baseline, same machine, same conditions.

| Proxy | Instance | vCPU | P50 overhead | RPS | Routing | Auth | Rate limit | Cache | DLP | Source |
|-------|----------|:----:|-------------:|----:|:-------:|:----:|:----------:|:-----:|:---:|--------|
| **Grob** | t3.xlarge | 4 | **127 µs** | 17.7k | Yes | Yes | Yes | Yes | — | [grob-bench](https://github.com/azerozero/grob-bench) |
| **Grob** | t3.xlarge | 4 | **161 µs** | 15.3k | Yes | Yes | Yes | Yes | Yes | [grob-bench](https://github.com/azerozero/grob-bench) |
| **Grob** | c7g.xlarge | 4 | **67 µs** | 35.5k | Yes | Yes | Yes | Yes | — | [grob-bench](https://github.com/azerozero/grob-bench) |
| **Grob** | c7g.xlarge | 4 | **90 µs** | 29.5k | Yes | Yes | Yes | Yes | Yes | [grob-bench](https://github.com/azerozero/grob-bench) |
| Bifrost | t3.xlarge | 4 | 11 µs | — | — | — | — | — | — | [Maxim blog](https://www.getmaxim.ai/blog/bifrost-a-drop-in-llm-proxy-40x-faster-than-litellm/) |
| TensorZero | c7i.xlarge | 4 | 370 µs | — | Yes | — | — | — | — | [TensorZero docs](https://www.tensorzero.com/docs/gateway/benchmarks) |
| LiteLLM | 4c / 8 GB | 4 | ~5 ms | — | Yes | Yes | Yes | — | — | [LiteLLM docs](https://docs.litellm.ai/docs/benchmarks) |

## Scaling by instance

All features enabled (routing + auth + rate limiting + cache + DLP).

| Instance | Type | Arch | vCPU | P50 | P95 | RPS | Overhead | RSS |
|----------|------|:----:|:----:|----:|----:|----:|---------:|----:|
| 4xl-arm | c7g.4xlarge | ARM64 | 16 | 174 µs | 209 µs | 88.6k | +113 µs | 65 MB |
| xlarge-arm | c7g.xlarge | ARM64 | 4 | 131 µs | 158 µs | 29.5k | +90 µs | 38 MB |
| xlarge-x86 | t3.xlarge | x86_64 | 4 | 249 µs | 301 µs | 15.3k | +161 µs | 29 MB |
| nano-arm | t4g.nano | ARM64 | 2 | 185 µs | 236 µs | 9.9k | +125 µs | 18 MB |
| medium-x86 | t3.medium | x86_64 | 2 | 235 µs | 273 µs | 8.1k | +161 µs | 21 MB |

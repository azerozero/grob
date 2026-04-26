# Benchmarks

> **90 µs overhead** with routing + auth + rate limiting + cache + DLP on 4 vCPU ARM — 40x faster than LiteLLM, with more features than Bifrost.

Run with `grob bench --concurrency` (c=vCPU, 5 sec/scenario, mock TCP backend on localhost). The numbers below were captured on the project's CI baseline; see [`Cargo.toml`](../../Cargo.toml) for the version they correspond to. Re-run locally to compare on your hardware.

> v0.26.0 added the HIT policy engine (SSE stream interception + approval channel). For requests without tool_use blocks the overhead is unchanged. For tool_use blocks requiring human approval, stream latency includes the approval wait time (not a grob bottleneck).
>
> v0.29.x adds combined proxy+policy scenarios — the policy matcher runs on every request in the hot path, validated by the `grob bench` suite.

**Policy evaluation overhead** (from `cargo bench --features policies -- policy_evaluate`):

| Rules | P50 | P95 |
|------:|----:|----:|
| 5 | ~1 µs | ~2 µs |
| 10 | ~2 µs | ~3 µs |
| 20 | ~3 µs | ~5 µs |
| 50 | ~7 µs | ~10 µs |

All within the ADR-0006 target of < 10 µs for 20 rules.

**Combined proxy+policy overhead** (routing + DLP + policy matcher, from `grob bench --concurrency`):

| Scenario | P50 overhead | Notes |
|----------|-------------:|-------|
| proxy only | ~18 µs | Routing + HTTP round-trip only |
| proxy + policy (5 rules) | ~19 µs | +1 µs — within ADR-0006 target |
| proxy + policy (20 rules) | ~21 µs | +3 µs — within ADR-0006 target |
| proxy + all (DLP + policy 20 rules) | ~90 µs | Full stack including DLP scan |

All within the ADR-0006 target of < 10 µs marginal cost for policy evaluation.

## Proxy overhead vs competitors

Overhead = P50 proxy − P50 direct baseline, same machine, same conditions.

| Proxy | Instance | vCPU | P50 overhead | req/s | Routing | Auth | Rate limit | Cache | DLP | Source |
|-------|----------|:----:|-------------:|------:|:-------:|:----:|:----------:|:-----:|:---:|--------|
| **Grob** | t3.xlarge | 4 | **127 µs** | 17,700 | Yes | Yes | Yes | Yes | — | [`benches/`](../../benches/) |
| **Grob** | t3.xlarge | 4 | **161 µs** | 15,300 | Yes | Yes | Yes | Yes | Yes | [`benches/`](../../benches/) |
| **Grob** | c7g.xlarge | 4 | **67 µs** | 35,500 | Yes | Yes | Yes | Yes | — | [`benches/`](../../benches/) |
| **Grob** | c7g.xlarge | 4 | **90 µs** | 29,500 | Yes | Yes | Yes | Yes | Yes | [`benches/`](../../benches/) |
| Bifrost | t3.xlarge | 4 | 11 µs | — | — | — | — | — | — | [Maxim blog](https://www.getmaxim.ai/blog/bifrost-a-drop-in-llm-proxy-40x-faster-than-litellm/) |
| TensorZero | c7i.xlarge | 4 | 370 µs | — | Yes | — | — | — | — | [TensorZero docs](https://www.tensorzero.com/docs/gateway/benchmarks) |
| LiteLLM | 4c / 8 GB | 4 | ~5 ms | — | Yes | Yes | Yes | — | — | [LiteLLM docs](https://docs.litellm.ai/docs/benchmarks) |

## Scaling by instance (AWS)

All features enabled (routing + auth + rate limiting + cache + DLP).

| Instance | Type | Arch | vCPU | P50 | P95 | req/s | Overhead | RSS |
|----------|------|:----:|:----:|----:|----:|------:|---------:|----:|
| 4xl-arm | c7g.4xlarge | ARM64 | 16 | 174 µs | 209 µs | 88,600 | +113 µs | 65 MB |
| xlarge-arm | c7g.xlarge | ARM64 | 4 | 131 µs | 158 µs | 29,500 | +90 µs | 38 MB |
| xlarge-x86 | t3.xlarge | x86_64 | 4 | 249 µs | 301 µs | 15,300 | +161 µs | 29 MB |
| nano-arm | t4g.nano | ARM64 | 2 | 185 µs | 236 µs | 9,900 | +125 µs | 18 MB |
| medium-x86 | t3.medium | x86_64 | 2 | 235 µs | 273 µs | 8,100 | +161 µs | 21 MB |

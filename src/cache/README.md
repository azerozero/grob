# cache

> Two-tier LLM response cache: exact SHA-256 lookup plus SimHash semantic fallback.

## Purpose
Avoids redundant upstream calls for deterministic (`temperature=0`) requests. The exact tier hashes the canonicalized request body; the SimHash tier accepts near-duplicates within a configurable Hamming distance so that paraphrased prompts can share a cached response. Re-emits cached bodies as Anthropic or OpenAI SSE on demand for streaming clients.

## Public API
| Item | Location | Used by |
|------|----------|---------|
| `ResponseCache::new`, `get`, `insert`, `stats` | `response_cache.rs` | `server::dispatch` |
| `CachedResponse` (body, content-type, provider, model) | `response_cache.rs` | dispatch, OpenAI compat |
| `CacheStats` | `response_cache.rs` | `/api/cache/stats` |
| `synthesize_anthropic_sse_from_cached` | `response_cache.rs` | streaming replay |
| `synthesize_openai_sse_from_cached` | `response_cache.rs` | OpenAI compat streaming |
| `SimHashCache`, `SimHashStats` | `simhash.rs` | `ResponseCache` (internal tier) |
| `simhash::normalize`, `compute`, `hamming_distance` | `simhash.rs` | tests, debug |

## Owns
- Moka concurrent cache with TTL, max-capacity, and per-entry size limits.
- SHA-256 keying with per-tenant prefix isolation.
- 64-bit SimHash computation (token-position-aware to keep "EN to FR" distinct from "FR to EN").
- Hamming-distance probe over the active SimHash entry set.
- Atomic counters for hits, misses, evictions, and `skipped_too_large` events.
- SSE replay synthesis for both Anthropic Messages and OpenAI Chat formats.

## Depends on
- `moka::future::Cache` (LRU + TTL).
- `sha2`, `serde`, `serde_json`.
- `crate::cli::CacheConfig` for runtime parameters.

## Non-goals
- Caching non-deterministic (`temperature>0`) responses. Callers gate that.
- Persistent storage. The cache is in-memory; restarts cold-start it.
- Provider semantics (e.g. tool-call replay correctness). Callers must flag uncacheable shapes.
- DLP redaction (handled before cache lookup).

## Tests
- `tests/integration/cache_test.rs` — end-to-end exact-tier and SimHash hits, eviction.
- `tests/integration/prompt_caching_test.rs` and `prompt_caching_comprehensive_test.rs` — SSE replay parity.
- Inline unit tests cover normalisation and Hamming distance.

## Related ADRs
- [ADR-0001](../../docs/decisions/0001-static-config-no-hot-reload.md) — Static cache config; reload swaps the whole cache atomically.

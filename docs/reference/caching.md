# Caching Reference

Grob includes an in-memory response cache backed by [moka](https://github.com/moka-rs/moka), a concurrent cache with TTL-based expiration. Caching eliminates redundant LLM calls for identical deterministic requests.

## When Responses Are Cached

A response is cached only when **all** of the following conditions are met:

- `[cache] enabled = true` in configuration.
- The request temperature is `0` or absent (unset). Any non-zero temperature makes the request non-deterministic and uncacheable.
- The request is **non-streaming** (`stream = false` or absent).
- The response body size does not exceed `max_entry_bytes`.

Streaming requests bypass the cache entirely -- both lookup and storage.

## Cache Key Computation

The cache key is a SHA-256 hex digest (64 characters) computed from these fields, separated by `|` delimiters:

1. **Tenant ID** (from JWT claims; `"anon"` if unauthenticated)
2. **Model name** (after routing / auto-mapping)
3. **Messages array** (JSON-serialized)
4. **System prompt** (JSON-serialized, if present)
5. **Tools** (JSON-serialized, if present)
6. **max_tokens** value

The serialization streams JSON bytes directly into the SHA-256 hasher via a `Sha256Writer` adapter, avoiding intermediate string allocations.

### Per-Tenant Isolation

The tenant ID is the first component of the cache key. This means tenant A and tenant B never share cached responses, even for identical requests. Unauthenticated requests all share the `"anon"` tenant namespace.

## Cache Hits

On a cache hit, the response includes:

- HTTP status `200`
- `content-type` header from the original cached response
- `x-grob-cache: hit` header
- Transparency headers (provider, model, request ID) if transparency is enabled

For streaming clients that receive a cache hit, Grob synthesizes a valid SSE stream from the cached non-streaming response body. Both Anthropic-native and OpenAI-compatible SSE formats are supported.

## Configuration

```toml
[cache]
enabled = true
max_capacity = 2000            # Maximum number of cached entries (default: 2000)
ttl_secs = 3600                # Time-to-live per entry in seconds (default: 3600 / 1 hour)
max_entry_bytes = 2097152      # Maximum single response size in bytes (default: 2 MiB)
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable or disable the response cache |
| `max_capacity` | integer | `2000` | Maximum number of entries the cache holds before eviction |
| `ttl_secs` | integer | `3600` | Seconds before an entry expires regardless of access |
| `max_entry_bytes` | integer | `2097152` (2 MiB) | Responses larger than this are not cached |

## Eviction

Moka handles eviction automatically:

- **TTL expiration**: entries expire after `ttl_secs` regardless of access frequency.
- **Capacity eviction**: when the cache reaches `max_capacity`, the least-recently-used entry is evicted.
- **Size skip**: responses exceeding `max_entry_bytes` are never inserted. The `skipped_too_large` counter tracks these occurrences.

All evictions are counted in the `evictions` statistic via an eviction listener.

## Metrics

The cache emits Prometheus-compatible metrics:

| Metric | Description |
|--------|-------------|
| `grob_cache_hits_total` | Number of cache hits |
| `grob_cache_misses_total` | Number of cache misses |
| `grob_cache_skipped_too_large_total` | Responses skipped due to size limit |

Internal statistics are also available programmatically via `cache.stats()`:

- `hits` -- total cache hits
- `misses` -- total cache misses
- `evictions` -- entries evicted by TTL or capacity
- `skipped_too_large` -- entries skipped due to size
- `entry_count` -- current number of entries

## Cache Invalidation

The `invalidate_all()` method clears all entries. This is a lazy operation in moka; entries are removed as pending tasks are processed.

## Pipeline Position

Cache lookup runs as Step 5 of the dispatch pipeline, after DLP input scanning and routing but before the provider loop:

1. DLP input scan
2. MCP tool calibration (if enabled)
3. Cache key computation (returns `None` for non-cacheable requests)
4. Route classification
5. Provider mapping resolution
6. **Cache lookup** (non-streaming only)
7. Fan-out or provider loop with fallback/retry

On a cache hit, steps 7+ are skipped entirely. On a cache miss after a successful provider response, the response is stored in the cache before being returned to the client.

## Full Example

```toml
[cache]
enabled = true
max_capacity = 5000
ttl_secs = 7200          # 2 hours
max_entry_bytes = 1048576 # 1 MiB -- skip caching very long responses

[router]
default = "smart"

[[models]]
name = "smart"
[[models.mappings]]
priority = 1
provider = "anthropic"
actual_model = "claude-sonnet-4-20250514"
```

With this configuration, identical `temperature=0` requests to the "smart" model are served from cache for up to 2 hours, avoiding redundant API calls. Responses larger than 1 MiB are passed through without caching.

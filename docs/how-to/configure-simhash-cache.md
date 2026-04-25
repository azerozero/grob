# Configure the SimHash fuzzy response cache

Grob caches deterministic LLM responses (`temperature = 0`) so that
identical or *near-identical* prompts can reuse a previous answer
without hitting the upstream provider. The cache has two layers:

- **Exact** — SHA-256 of the canonicalised request. Sub-microsecond
  lookup, zero false positives.
- **Fuzzy (SimHash)** — 64-bit perceptual fingerprint of the prompt
  text plus Hamming-distance lookup. Catches paraphrases, whitespace
  changes, and minor edits that the exact cache would miss.

The fuzzy layer uses *no* embeddings — the fingerprint is computed
from token shingles and `DefaultHasher`. It has no model dependency
and adds ~microseconds per request.

## How SimHash works (one paragraph)

The prompt is normalised (lowercased, punctuation stripped,
whitespace collapsed) and split into tokens. Each token is hashed
together with its position; per-bit weights are accumulated across
all tokens. The final 64-bit fingerprint has bit *i* set iff the
cumulative weight at position *i* is positive. Two similar prompts
share most bits; the **Hamming distance** (number of differing bits)
measures dissimilarity. Identical prompts → distance 0; complete
paraphrases → typically 1–4; unrelated prompts → typically > 20.

## Configure the cache

Add or update the `[cache]` section of `~/.grob/config.toml`:

```toml
[cache]
enabled = true
max_capacity = 2000          # entries (~4 MiB at 2 KiB avg)
ttl_secs = 3600              # 1 hour
max_entry_bytes = 2097152    # 2 MiB per entry
simhash_threshold = 3        # max Hamming distance for a fuzzy hit
```

Then reload:

```sh
curl -X POST http://localhost:13456/api/config/reload
```

## Tuning the threshold

`simhash_threshold` is the maximum Hamming distance for a cache hit.
Lower values are stricter; higher values are more permissive.

| Threshold | Behaviour | Use when |
|-----------|-----------|----------|
| `0` | Exact-match only (fingerprint must match perfectly) | You want the fuzzy layer disabled in practice |
| `1`–`2` | Catches whitespace and trivial edits | Conservative — minimise false positives |
| `3` (default) | Catches paraphrases of short prompts and small edits to long ones | Balanced |
| `4`–`6` | Catches synonym swaps, reordered tokens | Aggressive — boilerplate-heavy workloads |
| `≥ 10` | High false-positive risk — unrelated prompts may match | Not recommended |

A threshold of 3 over a 64-bit fingerprint is roughly a 5% Hamming
radius. Empirically this catches paraphrases without colliding
unrelated short prompts in production logs.

## Per-tenant isolation

The exact cache key includes the tenant ID, so cached responses are
never shared across virtual API keys. The SimHash layer keys on the
fingerprint only; if you need strict tenant isolation on the fuzzy
layer too, set `simhash_threshold = 0` for that deployment.

## Observability

Grob exports two Prometheus counters specific to the SimHash layer:

| Metric | Meaning |
|--------|---------|
| `grob_simhash_cache_hits_total` | Fuzzy lookups that returned a hit |
| `grob_simhash_cache_misses_total` | Fuzzy lookups with no entry within threshold |

Generic cache metrics (`grob_cache_hits_total`,
`grob_cache_misses_total`) cover both layers. To compute the fuzzy
**uplift** — share of hits the exact cache would have missed — divide
SimHash hits by total cache lookups.

## Disable the cache entirely

Set `enabled = false`. The SimHash layer is skipped along with the
exact layer; every request hits the upstream provider.

## Trade-offs

- **Latency**: SimHash adds ~1–5 µs per lookup (token hashing +
  fingerprint scan). Negligible compared to network round-trip.
- **Memory**: each fuzzy entry stores its 64-bit fingerprint plus a
  reference to the cached response. Bounded by `max_capacity`.
- **Determinism**: fuzzy hits return a response that was generated for
  a *similar but not identical* prompt. Always safe for explanatory or
  template-style prompts; can drift on prompts whose semantics depend
  on specific token order or wording. Test with representative
  workloads before raising the threshold above 3.

## Further reading

- [Configuration reference](../reference/configuration.md) — full list
  of `[cache]` options.
- [Auto-tune routing with trace analysis](auto-tune-routing.md) — pair
  the cache with classifier tuning for end-to-end speedup.

//! Semantic similarity cache using SimHash with Hamming distance.
//!
//! Provides fuzzy matching for LLM prompts so that semantically similar
//! requests can share cached responses, reducing redundant provider calls.

use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};

use moka::sync::Cache;

use super::response_cache::CachedResponse;

/// Default maximum Hamming distance for a cache hit.
const DEFAULT_THRESHOLD: u32 = 3;

/// Normalizes a prompt for SimHash computation.
///
/// Lowercases the input, collapses whitespace, and strips leading/trailing
/// punctuation from each token. Token **order is preserved** because it
/// carries semantic meaning ("translate English to French" is not the same
/// as "translate French to English").
pub fn normalize(input: &str) -> String {
    input
        .split_whitespace()
        .map(|t| t.to_lowercase())
        .map(|t| t.trim_matches(|c: char| !c.is_alphanumeric()).to_string())
        .filter(|t| !t.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Computes a 64-bit SimHash from an input string.
///
/// Splits the normalized input into whitespace-delimited tokens, hashes each
/// token together with its position via `DefaultHasher`, then accumulates
/// per-bit weights: +1 for set bits, -1 for unset bits. The final
/// fingerprint has bit *i* set iff the cumulative weight is positive.
pub fn compute(input: &str) -> u64 {
    let normalized = normalize(input);
    let tokens: Vec<&str> = normalized.split_whitespace().collect();

    if tokens.is_empty() {
        return 0;
    }

    let mut weights = [0i64; 64];

    for (pos, token) in tokens.iter().enumerate() {
        let hash = hash_token_at(token, pos);
        for (i, weight) in weights.iter_mut().enumerate() {
            if hash & (1u64 << i) != 0 {
                *weight += 1;
            } else {
                *weight -= 1;
            }
        }
    }

    weights.iter().enumerate().fold(
        0u64,
        |fp, (i, &w)| if w > 0 { fp | (1u64 << i) } else { fp },
    )
}

/// Computes the Hamming distance between two SimHash fingerprints.
///
/// Uses XOR + popcount to count the number of differing bits.
pub fn hamming_distance(a: u64, b: u64) -> u32 {
    (a ^ b).count_ones()
}

/// Hashes a token combined with its position using `DefaultHasher`.
///
/// Incorporating the position makes the fingerprint sensitive to token
/// order, so "translate English to French" differs from "translate French
/// to English".
fn hash_token_at(token: &str, position: usize) -> u64 {
    let mut hasher = std::hash::DefaultHasher::new();
    position.hash(&mut hasher);
    token.hash(&mut hasher);
    hasher.finish()
}

/// In-memory semantic cache keyed by SimHash fingerprints.
///
/// Backed by `moka::sync::Cache` for automatic TTL expiration and
/// capacity-bounded eviction, mirroring the exact cache's lifecycle.
/// Looks up the closest match within a configurable Hamming distance.
pub struct SimHashCache {
    inner: Cache<u64, CachedResponse>,
    threshold: u32,
    hits: AtomicU64,
    misses: AtomicU64,
}

/// Statistics for the SimHash cache layer.
#[derive(Debug, Clone, Default)]
pub struct SimHashStats {
    /// Number of fuzzy cache hits.
    pub hits: u64,
    /// Number of fuzzy cache misses.
    pub misses: u64,
    /// Current number of entries.
    pub entry_count: u64,
}

impl SimHashCache {
    /// Creates a new SimHash cache with default threshold.
    pub fn new(max_capacity: u64, ttl_secs: u64) -> Self {
        Self::with_threshold(DEFAULT_THRESHOLD, max_capacity, ttl_secs)
    }

    /// Creates a new SimHash cache with a custom Hamming distance threshold.
    pub fn with_threshold(threshold: u32, max_capacity: u64, ttl_secs: u64) -> Self {
        let cache = Cache::builder()
            .max_capacity(max_capacity)
            .time_to_live(std::time::Duration::from_secs(ttl_secs))
            .build();

        Self {
            inner: cache,
            threshold,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Looks up the closest cached response within the Hamming threshold.
    ///
    /// Iterates all live entries and returns the one with the smallest
    /// Hamming distance, provided it is within `threshold`. Returns `None`
    /// if no entry qualifies.
    pub fn get(&self, fingerprint: u64) -> Option<CachedResponse> {
        let mut best: Option<(u32, CachedResponse)> = None;

        for (stored_fp, resp) in &self.inner {
            let dist = hamming_distance(fingerprint, *stored_fp);
            if dist <= self.threshold {
                match best {
                    Some((best_dist, _)) if dist < best_dist => {
                        best = Some((dist, resp));
                    }
                    None => {
                        best = Some((dist, resp));
                    }
                    _ => {}
                }
            }
        }

        match best {
            Some((_, resp)) => {
                self.hits.fetch_add(1, Ordering::Relaxed);
                metrics::counter!("grob_simhash_cache_hits_total").increment(1);
                Some(resp)
            }
            None => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                metrics::counter!("grob_simhash_cache_misses_total").increment(1);
                None
            }
        }
    }

    /// Stores a response under the given SimHash fingerprint.
    pub fn put(&self, fingerprint: u64, response: CachedResponse) {
        self.inner.insert(fingerprint, response);
    }

    /// Returns current cache statistics.
    pub fn stats(&self) -> SimHashStats {
        SimHashStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            entry_count: self.inner.entry_count(),
        }
    }

    /// Removes all entries from the cache.
    pub fn clear(&self) {
        self.inner.invalidate_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- normalize -----------------------------------------------------------

    #[test]
    fn normalize_lowercases() {
        assert_eq!(normalize("Hello World"), "hello world");
    }

    #[test]
    fn normalize_strips_extra_whitespace() {
        assert_eq!(normalize("  foo   bar  "), "foo bar");
    }

    #[test]
    fn normalize_preserves_token_order() {
        assert_eq!(
            normalize("translate English to French"),
            "translate english to french"
        );
        // Order matters for semantics.
        assert_ne!(
            normalize("translate English to French"),
            normalize("translate French to English"),
        );
    }

    #[test]
    fn normalize_strips_punctuation() {
        assert_eq!(normalize("hello, world!"), "hello world");
        assert_eq!(normalize("what?"), "what");
    }

    #[test]
    fn normalize_empty_input() {
        assert_eq!(normalize(""), "");
        assert_eq!(normalize("   "), "");
    }

    // -- compute (SimHash) ---------------------------------------------------

    #[test]
    fn identical_prompts_produce_same_hash() {
        let a = compute("What is the capital of France?");
        let b = compute("What is the capital of France?");
        assert_eq!(a, b);
    }

    #[test]
    fn case_insensitive_prompts_produce_same_hash() {
        let a = compute("What is the capital of France");
        let b = compute("what is the capital of france");
        assert_eq!(a, b);
    }

    #[test]
    fn reordered_prompts_produce_different_hash() {
        // Token order is preserved, so different order means different hash.
        let a = compute("translate English to French");
        let b = compute("translate French to English");
        assert_ne!(a, b);
    }

    #[test]
    fn similar_prompts_are_close() {
        let a = compute("What is the capital of France");
        let b = compute("What is the capital of Germany");
        let dist = hamming_distance(a, b);
        assert!(dist <= 20, "expected close hashes, got distance {dist}");
    }

    #[test]
    fn very_different_prompts_are_far() {
        let a = compute("What is the capital of France?");
        let b = compute("Explain quantum entanglement in simple terms");
        let dist = hamming_distance(a, b);
        assert!(dist > 3, "expected distant hashes, got distance {dist}");
    }

    #[test]
    fn empty_input_returns_zero() {
        assert_eq!(compute(""), 0);
    }

    // -- hamming_distance ----------------------------------------------------

    #[test]
    fn hamming_identical() {
        assert_eq!(hamming_distance(0xDEAD_BEEF, 0xDEAD_BEEF), 0);
    }

    #[test]
    fn hamming_one_bit() {
        assert_eq!(hamming_distance(0b1000, 0b0000), 1);
    }

    #[test]
    fn hamming_all_bits() {
        assert_eq!(hamming_distance(0, u64::MAX), 64);
    }

    // -- SimHashCache --------------------------------------------------------

    fn make_cache() -> SimHashCache {
        SimHashCache::new(100, 60)
    }

    fn make_cache_with_threshold(threshold: u32) -> SimHashCache {
        SimHashCache::with_threshold(threshold, 100, 60)
    }

    #[test]
    fn cache_exact_hit() {
        let cache = make_cache();
        let fp = compute("Hello world");
        let resp = make_response("cached-body");
        cache.put(fp, resp.clone());

        let hit = cache.get(fp);
        assert!(hit.is_some());
        assert_eq!(hit.unwrap().body, resp.body);
        assert_eq!(cache.stats().hits, 1);
    }

    #[test]
    fn cache_fuzzy_hit_within_threshold() {
        let cache = make_cache_with_threshold(3);
        let fp_stored = compute("What is the capital of France");
        cache.put(fp_stored, make_response("france-answer"));

        // Same prompt different casing — normalizes identically, dist == 0.
        let fp_query = compute("what is the Capital of France");
        let dist = hamming_distance(fp_stored, fp_query);
        assert_eq!(dist, 0);
        assert!(cache.get(fp_query).is_some());
    }

    #[test]
    fn cache_miss_beyond_threshold() {
        let cache = make_cache_with_threshold(3);
        let fp_stored = compute("What is the capital of France?");
        cache.put(fp_stored, make_response("france-answer"));

        let fp_query = compute("Explain quantum entanglement in simple terms");
        assert!(cache.get(fp_query).is_none());
        assert_eq!(cache.stats().misses, 1);
    }

    #[test]
    fn cache_picks_closest_match() {
        let cache = make_cache_with_threshold(10);

        let fp_a = 0b0000_0000u64;
        let fp_b = 0b0000_0011u64; // distance 2 from fp_a
        let fp_c = 0b0000_1111u64; // distance 4 from fp_a

        cache.put(fp_b, make_response("closer"));
        cache.put(fp_c, make_response("farther"));

        let hit = cache.get(fp_a).unwrap();
        assert_eq!(hit.body, b"closer");
    }

    #[test]
    fn cache_clear() {
        let cache = make_cache();
        cache.put(42, make_response("data"));
        assert!(cache.get(42).is_some());
        cache.clear();
        // moka invalidate_all is lazy — run pending tasks to flush.
        cache.inner.run_pending_tasks();
        assert!(cache.get(42).is_none());
    }

    #[test]
    fn cache_stats_initial() {
        let cache = make_cache();
        let stats = cache.stats();
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 0);
        assert_eq!(stats.entry_count, 0);
    }

    // -- helpers -------------------------------------------------------------

    fn make_response(body: &str) -> CachedResponse {
        CachedResponse {
            body: body.as_bytes().to_vec(),
            content_type: "application/json".to_string(),
            provider: "test".to_string(),
            model: "test-model".to_string(),
        }
    }
}

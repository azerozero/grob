//! LLM response cache configuration.

use serde::{Deserialize, Serialize};

/// LLM response cache configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CacheConfig {
    /// Enable response caching (only for temperature=0 requests)
    #[serde(default)]
    pub enabled: bool,
    /// Maximum number of cached responses
    #[serde(default = "default_cache_max_capacity")]
    pub max_capacity: u64,
    /// TTL in seconds for cached entries
    #[serde(default = "default_cache_ttl")]
    pub ttl_secs: u64,
    /// Maximum single entry size in bytes (skip caching responses larger than this)
    #[serde(default = "default_cache_max_entry_bytes")]
    pub max_entry_bytes: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_capacity: default_cache_max_capacity(),
            ttl_secs: default_cache_ttl(),
            max_entry_bytes: default_cache_max_entry_bytes(),
        }
    }
}

// NOTE: 2000 entries at ~2 KiB avg response = ~4 MiB memory. Enough for a
// full day of Claude Code sessions with temperature=0 (highly cacheable).
fn default_cache_max_capacity() -> u64 {
    2000
}

// NOTE: 1 hour balances freshness (model behavior doesn't change intra-hour)
// vs hit rate. Longer TTLs risk stale responses after provider updates.
fn default_cache_ttl() -> u64 {
    3600
}

// NOTE: 2 MiB covers 99%+ of LLM responses. Responses above this threshold
// (e.g., large code generation) have low cache hit probability anyway.
fn default_cache_max_entry_bytes() -> usize {
    2 * 1024 * 1024
}

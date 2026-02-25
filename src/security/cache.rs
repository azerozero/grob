//! High-performance cache layer using Moka
//!
//! Provides TTL-based caching for:
//! - JWT token validation results
//! - Rate limit buckets
//! - Provider metadata
//!
//! Conforms to HDS/SecNumCloud requirements with automatic expiration.

use moka::future::Cache;
use std::time::Duration;

/// Cache entry for JWT validation
#[derive(Debug, Clone)]
pub struct JwtCacheEntry {
    /// Claims extracted from the token
    pub claims: crate::auth::jwt::GrobClaims,
    /// Token hash for cache key verification
    pub token_hash: String,
}

/// JWT validation cache
/// Tokens are cached for a short period to avoid repeated signature verification
pub type JwtValidationCache = Cache<String, JwtCacheEntry>;

/// Token bucket cache for rate limiting
/// Keys expire automatically after inactivity (TTL)
pub type RateLimitCache<V> = Cache<String, V>;

/// Provider metadata cache
/// Caches model lists, pricing info, etc.
#[derive(Debug, Clone)]
pub struct ProviderMetadata {
    pub models: Vec<String>,
    pub pricing: std::collections::HashMap<String, f64>,
    pub fetched_at: chrono::DateTime<chrono::Utc>,
}

pub type ProviderMetadataCache = Cache<String, ProviderMetadata>;

/// Create a JWT validation cache
/// TTL: 5 minutes (tokens are re-validated periodically)
pub fn jwt_validation_cache(max_capacity: u64) -> JwtValidationCache {
    Cache::builder()
        .max_capacity(max_capacity)
        .time_to_live(Duration::from_secs(300)) // 5 minutes
        .name("jwt_validation")
        .build()
}

/// Create a rate limit cache with custom TTL
/// Entries expire after inactivity (default: 10 minutes)
pub fn rate_limit_cache<V: Clone + Send + Sync + 'static>(
    max_capacity: u64,
    ttl_seconds: u64,
) -> Cache<String, V> {
    Cache::builder()
        .max_capacity(max_capacity)
        .time_to_idle(Duration::from_secs(ttl_seconds))
        .name("rate_limit")
        .build()
}

/// Create a provider metadata cache
/// TTL: 1 hour (infrequently changing data)
pub fn provider_metadata_cache(max_capacity: u64) -> ProviderMetadataCache {
    Cache::builder()
        .max_capacity(max_capacity)
        .time_to_live(Duration::from_secs(3600)) // 1 hour
        .name("provider_metadata")
        .build()
}

/// Hash a token for cache key generation
pub fn hash_token(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())[..32].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_token() {
        let token1 = "header.payload.signature";
        let token2 = "header.payload.signature";
        let token3 = "different.token.here";

        assert_eq!(hash_token(token1), hash_token(token2));
        assert_ne!(hash_token(token1), hash_token(token3));
    }

    #[tokio::test]
    async fn test_jwt_cache_insert_get() {
        let cache = jwt_validation_cache(100);
        let token_hash = hash_token("test.token.here");

        let entry = JwtCacheEntry {
            claims: crate::auth::jwt::GrobClaims {
                sub: "user-123".to_string(),
                tenant: None,
                exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as u64,
                iss: None,
                aud: None,
            },
            token_hash: token_hash.clone(),
        };

        cache.insert(token_hash.clone(), entry.clone()).await;

        let cached = cache.get(&token_hash).await;
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().claims.sub, "user-123");
    }

    #[tokio::test]
    async fn test_rate_limit_cache_ttl() {
        // Create cache with very short TTL for testing
        let cache = Cache::builder()
            .max_capacity(100)
            .time_to_idle(Duration::from_millis(50))
            .build();

        cache.insert("key1".to_string(), 42i32).await;
        assert_eq!(cache.get("key1").await, Some(42));

        // Wait for TTL
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Entry should be expired
        assert_eq!(cache.get("key1").await, None);
    }
}

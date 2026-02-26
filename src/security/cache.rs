//! High-performance cache layer using Moka
//!
//! Provides TTL-based caching for:
//! - JWT token validation results
//!
//! Conforms to HDS/SecNumCloud requirements with automatic expiration.

use moka::future::Cache;
use std::time::Duration;

/// Cache entry for JWT validation
#[derive(Debug, Clone)]
pub struct JwtCacheEntry {
    /// Claims extracted from the token
    pub _claims: crate::auth::jwt::GrobClaims,
    /// Token hash for cache key verification
    pub _token_hash: String,
}

/// JWT validation cache
/// Tokens are cached for a short period to avoid repeated signature verification
pub type JwtValidationCache = Cache<String, JwtCacheEntry>;

/// Create a JWT validation cache
/// TTL: 5 minutes (tokens are re-validated periodically)
pub fn jwt_validation_cache(max_capacity: u64) -> JwtValidationCache {
    Cache::builder()
        .max_capacity(max_capacity)
        .time_to_live(Duration::from_secs(300)) // 5 minutes
        .name("jwt_validation")
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_jwt_cache_insert_get() {
        let cache = jwt_validation_cache(100);

        let entry = JwtCacheEntry {
            _claims: crate::auth::jwt::GrobClaims {
                sub: "user-123".to_string(),
                tenant: None,
                exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as u64,
                iss: None,
                aud: None,
            },
            _token_hash: "testhash".to_string(),
        };

        cache.insert("testhash".to_string(), entry.clone()).await;

        let cached = cache.get(&"testhash".to_string()).await;
        assert!(cached.is_some());
    }
}

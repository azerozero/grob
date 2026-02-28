//! Rate limiting per tenant/API key for Grob
//! Conforms to HDS/SecNumCloud/NIS2 requirements
//!
//! Implements token bucket algorithm with per-tenant tracking

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Rate limit configuration per tier
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Requests per second
    pub requests_per_second: u32,
    /// Burst capacity
    pub burst: u32,
}

/// Token bucket state using integer milli-tokens (1000 = 1 full token)
#[derive(Debug)]
struct TokenBucket {
    tokens_milli: u64,
    last_update: Instant,
    rps: u32,
    burst_milli: u64,
}

impl TokenBucket {
    fn new(config: RateLimitConfig) -> Self {
        Self {
            tokens_milli: config.burst as u64 * 1000,
            last_update: Instant::now(),
            rps: config.requests_per_second,
            burst_milli: config.burst as u64 * 1000,
        }
    }

    /// Try to consume a token, returns true if allowed
    fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed_ms = now.duration_since(self.last_update).as_millis() as u64;
        self.last_update = now;

        // Add tokens based on elapsed time (milli-tokens)
        self.tokens_milli =
            (self.tokens_milli + elapsed_ms * self.rps as u64).min(self.burst_milli);

        if self.tokens_milli >= 1000 {
            self.tokens_milli -= 1000;
            true
        } else {
            false
        }
    }

    /// Get remaining tokens (for headers)
    fn remaining(&self) -> u32 {
        (self.tokens_milli / 1000) as u32
    }
}

/// Rate limiter key (tenant_id or IP fallback)
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum RateLimitKey {
    Tenant(String),
    Ip(String),
}

/// Rate limiter with automatic cleanup
pub struct RateLimiter {
    /// Buckets per key
    buckets: Arc<RwLock<HashMap<RateLimitKey, TokenBucket>>>,
    /// Default config
    default_config: RateLimitConfig,
    /// Cleanup interval
    _cleanup_interval: Duration,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        let buckets = Arc::new(RwLock::new(HashMap::new()));
        let cleanup_interval = Duration::from_secs(300); // 5 minutes

        // Spawn cleanup task
        let buckets_clone = Arc::clone(&buckets);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(cleanup_interval);
            loop {
                interval.tick().await;
                Self::cleanup_stale_buckets(&buckets_clone).await;
            }
        });

        Self {
            buckets,
            default_config: config,
            _cleanup_interval: cleanup_interval,
        }
    }

    /// Check if request is allowed, returns (allowed, remaining, reset_after)
    pub async fn check(&self, key: &RateLimitKey) -> (bool, u32, Option<Duration>) {
        let mut buckets = self.buckets.write().await;

        let bucket = buckets
            .entry(key.clone())
            .or_insert_with(|| TokenBucket::new(self.default_config.clone()));

        let allowed = bucket.try_consume();
        let remaining = bucket.remaining();

        let reset_after = if allowed {
            None
        } else {
            // Calculate time until 1 token is available (using milli-tokens)
            let needed_milli = 1000u64.saturating_sub(bucket.tokens_milli);
            let ms = needed_milli / self.default_config.requests_per_second.max(1) as u64;
            Some(Duration::from_millis(ms))
        };

        (allowed, remaining, reset_after)
    }

    /// Cleanup stale buckets (idle > 10 minutes)
    async fn cleanup_stale_buckets(buckets: &Arc<RwLock<HashMap<RateLimitKey, TokenBucket>>>) {
        const IDLE_TIMEOUT: Duration = Duration::from_secs(600);
        let now = Instant::now();

        let mut buckets = buckets.write().await;
        let stale_keys: Vec<_> = buckets
            .iter()
            .filter(|(_, bucket)| now.duration_since(bucket.last_update) > IDLE_TIMEOUT)
            .map(|(k, _)| k.clone())
            .collect();

        for key in stale_keys {
            buckets.remove(&key);
            tracing::debug!("Removed stale rate limit bucket for {:?}", key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_token_bucket() {
        let config = RateLimitConfig {
            requests_per_second: 10,
            burst: 5,
        };

        let mut bucket = TokenBucket::new(config);

        // Should allow burst
        assert!(bucket.try_consume());
        assert!(bucket.try_consume());
        assert!(bucket.try_consume());
        assert!(bucket.try_consume());
        assert!(bucket.try_consume());

        // Should reject after burst
        assert!(!bucket.try_consume());

        // Wait and check refill
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(bucket.try_consume()); // 1 token refilled
    }

    #[tokio::test]
    async fn test_rate_limiter() {
        let limiter = RateLimiter::new(RateLimitConfig {
            requests_per_second: 100,
            burst: 10,
        });

        let key = RateLimitKey::Tenant("test-tenant".to_string());

        // Should allow burst
        for _ in 0..10 {
            let (allowed, _, _) = limiter.check(&key).await;
            assert!(allowed);
        }

        // Should reject after burst
        let (allowed, remaining, reset) = limiter.check(&key).await;
        assert!(!allowed);
        assert_eq!(remaining, 0);
        assert!(reset.is_some());
    }
}

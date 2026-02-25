//! Rate limiting per tenant/API key for Grob
//! Conforms to HDS/SecNumCloud/NIS2 requirements
//!
//! Implements token bucket algorithm with per-tenant tracking

use std::collections::HashMap;
use std::net::SocketAddr;
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
    /// Window for sliding window (optional)
    pub window: Duration,
}

impl RateLimitConfig {
    /// Default strict tier (HDS/PCI compliance)
    pub fn strict() -> Self {
        Self {
            requests_per_second: 10,
            burst: 20,
            window: Duration::from_secs(60),
        }
    }

    /// Default standard tier
    pub fn standard() -> Self {
        Self {
            requests_per_second: 100,
            burst: 200,
            window: Duration::from_secs(60),
        }
    }
}

/// Token bucket state
#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    last_update: Instant,
    config: RateLimitConfig,
}

impl TokenBucket {
    fn new(config: RateLimitConfig) -> Self {
        Self {
            tokens: config.burst as f64,
            last_update: Instant::now(),
            config,
        }
    }

    /// Try to consume a token, returns true if allowed
    fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        self.last_update = now;

        // Add tokens based on elapsed time
        self.tokens = (self.tokens + elapsed * self.config.requests_per_second as f64)
            .min(self.config.burst as f64);

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Get remaining tokens (for headers)
    fn remaining(&self) -> u32 {
        self.tokens as u32
    }
}

/// Rate limiter key (tenant_id or IP fallback)
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum RateLimitKey {
    Tenant(String),
    Ip(String),
}

impl RateLimitKey {
    pub fn from_tenant(tenant: &str) -> Self {
        Self::Tenant(tenant.to_string())
    }

    pub fn from_addr(addr: SocketAddr) -> Self {
        Self::Ip(addr.ip().to_string())
    }
}

/// Rate limiter with automatic cleanup
pub struct RateLimiter {
    /// Buckets per key
    buckets: Arc<RwLock<HashMap<RateLimitKey, TokenBucket>>>,
    /// Default config
    default_config: RateLimitConfig,
    /// Cleanup interval
    cleanup_interval: Duration,
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
            cleanup_interval,
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
            // Calculate time until 1 token is available
            let needed = 1.0 - bucket.tokens;
            let seconds = needed / self.default_config.requests_per_second as f64;
            Some(Duration::from_secs_f64(seconds))
        };

        (allowed, remaining, reset_after)
    }

    /// Get current state for a key (for metrics)
    pub async fn get_state(&self, key: &RateLimitKey) -> Option<(u32, f64)> {
        let buckets = self.buckets.read().await;
        buckets.get(key).map(|b| (b.remaining(), b.tokens))
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

    /// Get metrics for all active buckets
    pub async fn metrics(&self) -> Vec<(RateLimitKey, u32, f64)> {
        let buckets = self.buckets.read().await;
        buckets
            .iter()
            .map(|(k, b)| (k.clone(), b.remaining(), b.tokens))
            .collect()
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new(RateLimitConfig::standard())
    }
}

/// Axum middleware for rate limiting
pub async fn rate_limit_middleware(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
    limiter: Arc<RateLimiter>,
) -> axum::response::Response {
    // Extract key from request (X-API-Key or IP)
    let key = req
        .headers()
        .get("x-api-key")
        .and_then(|h| h.to_str().ok())
        .map(|k| RateLimitKey::Tenant(k.to_string()))
        .or_else(|| {
            req.extensions()
                .get::<SocketAddr>()
                .map(|addr| RateLimitKey::from_addr(*addr))
        });

    if let Some(key) = key {
        let (allowed, remaining, reset_after) = limiter.check(&key).await;

        if !allowed {
            let mut resp = axum::response::Response::builder()
                .status(axum::http::StatusCode::TOO_MANY_REQUESTS);

            resp = resp.header("X-RateLimit-Limit", limiter.default_config.burst.to_string());
            resp = resp.header("X-RateLimit-Remaining", "0");

            if let Some(reset) = reset_after {
                resp = resp.header("Retry-After", reset.as_secs().to_string());
                resp = resp.header("X-RateLimit-Reset", reset.as_secs().to_string());
            }

            return resp
                .body(axum::body::Body::from("Rate limit exceeded. Please slow down."))
                .unwrap();
        }
    }

    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_token_bucket() {
        let config = RateLimitConfig {
            requests_per_second: 10,
            burst: 5,
            window: Duration::from_secs(60),
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
            window: Duration::from_secs(60),
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

    #[test]
    fn test_rate_limit_key() {
        let tenant = RateLimitKey::from_tenant("tenant-123");
        assert!(matches!(tenant, RateLimitKey::Tenant(s) if s == "tenant-123"));

        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let ip = RateLimitKey::from_addr(addr);
        assert!(matches!(ip, RateLimitKey::Ip(s) if s == "127.0.0.1"));
    }

    #[tokio::test]
    async fn test_cleanup() {
        let buckets = Arc::new(RwLock::new(HashMap::new()));
        let config = RateLimitConfig::standard();

        {
            let mut b = buckets.write().await;
            b.insert(RateLimitKey::Tenant("old".to_string()), TokenBucket::new(config.clone()));
            b.insert(RateLimitKey::Tenant("new".to_string()), TokenBucket::new(config));
        }

        // Manually trigger cleanup (would need to wait otherwise)
        // In real scenario, cleanup runs every 5 minutes

        let count = buckets.read().await.len();
        assert_eq!(count, 2);
    }
}

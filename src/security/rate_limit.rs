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

/// Scales a fleet-wide limit down to one replica's share.
///
/// `N` replicas each enforcing the configured limit let the fleet through
/// `N * limit`. Dividing by the replica count and withholding a margin turns
/// the configured number into a ceiling the fleet cannot exceed — with no
/// coordination at all: no shared store, no gossip, not one packet.
///
/// The floor of `1` is deliberate. A large fleet with a small limit would
/// otherwise round each share down to zero and reject **all** traffic, turning
/// a rate limiter into an outage. Overshooting a tiny limit is a far better
/// failure than serving nothing, so the share never drops below one.
///
/// Returns the input unchanged for a single replica with no margin, so the
/// default deployment is bit-for-bit unaffected.
#[must_use]
pub fn replica_share(limit: u32, replicas: u32, margin_percent: u32) -> u32 {
    if limit == 0 {
        // 0 means "no limit configured"; scaling it would invent one.
        return 0;
    }
    let replicas = replicas.max(1);
    // Cap the margin below 100: a 100% margin would withhold the entire quota.
    let margin = margin_percent.min(99);

    let after_margin = u64::from(limit) * u64::from(100 - margin) / 100;
    let share = after_margin / u64::from(replicas);

    // Never fewer than one token: see the floor rationale above.
    u32::try_from(share).unwrap_or(u32::MAX).max(1)
}

/// Rate limiter key (tenant_id or IP fallback)
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum RateLimitKey {
    /// Keyed by tenant identifier.
    Tenant(String),
    /// Keyed by source IP address (fallback).
    Ip(String),
    /// Keyed by OIDC client (`azp` / `client_id`).
    ///
    /// A separate variant rather than a prefixed [`RateLimitKey::Tenant`] so a
    /// client id can never collide with a tenant id that happens to share the
    /// same string, which would silently merge two different principals into
    /// one bucket.
    Client(String),
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
    /// Creates a rate limiter and spawns a background cleanup task.
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

    /// Like [`RateLimiter::check`], but enforces `rps` for this key's bucket.
    ///
    /// Used for per-policy `rate_limit` overrides, where the rate is decided per
    /// request (not from the limiter's default config). The bucket's rate is set
    /// to `rps` on every call so a policy change takes effect immediately; burst
    /// equals `rps` (min 1) so a key may spend up to `rps` tokens before
    /// throttling. Use a dedicated limiter instance for this so the buckets never
    /// collide with the middleware's default-rate buckets.
    pub async fn check_with_rps(
        &self,
        key: &RateLimitKey,
        rps: u32,
    ) -> (bool, u32, Option<Duration>) {
        let rps = rps.max(1);
        let mut buckets = self.buckets.write().await;
        let bucket = buckets.entry(key.clone()).or_insert_with(|| {
            TokenBucket::new(RateLimitConfig {
                requests_per_second: rps,
                burst: rps,
            })
        });
        // Honour the current policy's rps even if the bucket predates it.
        bucket.rps = rps;
        let allowed = bucket.try_consume();
        let remaining = bucket.remaining();
        let reset_after = if allowed {
            None
        } else {
            let needed_milli = 1000u64.saturating_sub(bucket.tokens_milli);
            Some(Duration::from_millis(needed_milli / rps as u64))
        };
        (allowed, remaining, reset_after)
    }

    /// Like [`RateLimiter::check`], but overrides this key's rate **and** burst.
    ///
    /// Distinct from [`RateLimiter::check_with_rps`], which pins `burst = rps`
    /// and is meant for a dedicated policy limiter. Per-client overrides share
    /// the middleware's limiter, where the deployment's configured burst is a
    /// separate knob and must be preserved: collapsing it to `rps` would
    /// silently remove the burst allowance for exactly the clients that were
    /// given a custom rate.
    pub async fn check_with_config(
        &self,
        key: &RateLimitKey,
        config: RateLimitConfig,
    ) -> (bool, u32, Option<Duration>) {
        let rps = config.requests_per_second.max(1);
        let burst_milli = config.burst.max(1) as u64 * 1000;

        let mut buckets = self.buckets.write().await;
        let bucket = buckets
            .entry(key.clone())
            .or_insert_with(|| TokenBucket::new(config.clone()));

        // Honour the current configuration even if the bucket predates it, so a
        // config reload takes effect without waiting for bucket expiry.
        bucket.rps = rps;
        bucket.burst_milli = burst_milli;
        bucket.tokens_milli = bucket.tokens_milli.min(burst_milli);

        let allowed = bucket.try_consume();
        let remaining = bucket.remaining();
        let reset_after = if allowed {
            None
        } else {
            let needed_milli = 1000u64.saturating_sub(bucket.tokens_milli);
            Some(Duration::from_millis(needed_milli / rps as u64))
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

    /// Distinct clients must not share a bucket.
    ///
    /// The whole point of keying by client: exhausting one application's quota
    /// must not throttle another.
    #[tokio::test]
    async fn client_keys_are_isolated() {
        let limiter = RateLimiter::new(RateLimitConfig {
            requests_per_second: 1,
            burst: 1,
        });
        let a = RateLimitKey::Client("app-a".to_string());
        let b = RateLimitKey::Client("app-b".to_string());

        assert!(limiter.check(&a).await.0, "first request for app-a passes");
        assert!(!limiter.check(&a).await.0, "app-a is now out of tokens");
        assert!(
            limiter.check(&b).await.0,
            "app-b must be unaffected by app-a exhausting its bucket"
        );
    }

    /// A client id must not collide with an identical tenant id.
    ///
    /// Both are user-controlled strings from different namespaces. If the key
    /// were a prefixed string rather than a distinct variant, a tenant named
    /// like a client would silently share its quota.
    #[tokio::test]
    async fn client_and_tenant_keys_do_not_collide() {
        let limiter = RateLimiter::new(RateLimitConfig {
            requests_per_second: 1,
            burst: 1,
        });
        let as_client = RateLimitKey::Client("same-name".to_string());
        let as_tenant = RateLimitKey::Tenant("same-name".to_string());

        assert!(limiter.check(&as_client).await.0);
        assert!(!limiter.check(&as_client).await.0, "client bucket drained");
        assert!(
            limiter.check(&as_tenant).await.0,
            "a tenant sharing the client's name must have its own bucket"
        );
    }

    /// A per-client override must apply its own rate *and* burst.
    #[tokio::test]
    async fn check_with_config_applies_rate_and_burst() {
        let limiter = RateLimiter::new(RateLimitConfig {
            requests_per_second: 1,
            burst: 1,
        });
        let key = RateLimitKey::Client("batch".to_string());
        let generous = RateLimitConfig {
            requests_per_second: 50,
            burst: 5,
        };

        // Five requests fit the overridden burst, where the default allowed one.
        for i in 0..5 {
            assert!(
                limiter.check_with_config(&key, generous.clone()).await.0,
                "request {i} must fit the overridden burst of 5"
            );
        }
        assert!(
            !limiter.check_with_config(&key, generous).await.0,
            "the sixth must be throttled: an override raises the limit, not removes it"
        );
    }

    /// A config change must take effect on an existing bucket.
    ///
    /// Buckets outlive a reload, so an override that only applied to freshly
    /// created buckets would leave live clients on the old quota until they
    /// went idle for ten minutes.
    ///
    /// Note what is asserted: raising the rate does **not** instantly grant
    /// tokens (a token bucket accrues them over time, and handing out a windfall
    /// on every reload would let a client burst past its quota by triggering
    /// reloads). What must change is the *refill speed*.
    #[tokio::test]
    async fn check_with_config_updates_an_existing_bucket() {
        let tight = RateLimitConfig {
            requests_per_second: 1,
            burst: 1,
        };
        let loose = RateLimitConfig {
            requests_per_second: 200,
            burst: 10,
        };

        // Baseline: at 1 rps, 30 ms is far too short to earn a token back.
        let limiter = RateLimiter::new(tight.clone());
        let key = RateLimitKey::Client("app".to_string());
        assert!(limiter.check_with_config(&key, tight.clone()).await.0);
        assert!(!limiter.check_with_config(&key, tight.clone()).await.0);
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(
            !limiter.check_with_config(&key, tight).await.0,
            "at 1 rps the bucket must still be empty after 30 ms"
        );

        // Same bucket, raised quota: the same wait now refills it.
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(
            limiter.check_with_config(&key, loose).await.0,
            "the raised rate must apply to the bucket that already exists"
        );
    }

    /// The default deployment must be bit-for-bit unchanged.
    #[test]
    fn single_replica_no_margin_is_identity() {
        assert_eq!(replica_share(100, 1, 0), 100);
        assert_eq!(replica_share(7, 1, 0), 7);
    }

    /// The fleet total must never exceed the configured limit.
    ///
    /// This is the whole point: the configured number becomes a real ceiling
    /// instead of a per-replica one that multiplies by the replica count.
    #[test]
    fn fleet_total_never_exceeds_the_configured_limit() {
        for limit in [10u32, 100, 1000, 9999] {
            for replicas in 1u32..=16 {
                for margin in [0u32, 5, 20] {
                    let share = replica_share(limit, replicas, margin);
                    let fleet_total = u64::from(share) * u64::from(replicas);
                    // The floor of 1 can overshoot a limit smaller than the
                    // replica count; that case is asserted separately below.
                    if u64::from(limit) >= u64::from(replicas) {
                        assert!(
                            fleet_total <= u64::from(limit),
                            "limit={limit} replicas={replicas} margin={margin}: \
                             fleet total {fleet_total} exceeds the configured limit"
                        );
                    }
                }
            }
        }
    }

    /// The margin is withheld from the fleet limit, as a percentage.
    #[test]
    fn margin_withholds_the_requested_share() {
        // 1000 rps over 4 replicas, 5% withheld → 950 / 4 = 237.
        assert_eq!(replica_share(1000, 4, 5), 237);
        // 20% withheld → 800 / 4 = 200.
        assert_eq!(replica_share(1000, 4, 20), 200);
        // Margin alone, single replica.
        assert_eq!(replica_share(1000, 1, 10), 900);
    }

    /// A limit smaller than the fleet must not reject everything.
    ///
    /// Dividing 5 rps across 10 replicas rounds each share to zero. Enforcing
    /// that would serve **no** traffic at all — a rate limiter becoming the
    /// outage it exists to prevent. Overshooting a tiny limit is the better
    /// failure, so the share floors at one.
    #[test]
    fn share_never_floors_to_zero() {
        assert_eq!(replica_share(5, 10, 0), 1, "must not reject all traffic");
        assert_eq!(replica_share(1, 100, 0), 1);
        // Even a pathological margin leaves one token.
        assert_eq!(replica_share(10, 2, 99), 1);
        assert_eq!(replica_share(10, 2, 100), 1, "margin is capped below 100%");
    }

    /// An unconfigured limit must stay unconfigured.
    ///
    /// Scaling zero would invent a limit where the operator asked for none.
    #[test]
    fn zero_limit_stays_zero() {
        assert_eq!(replica_share(0, 8, 20), 0);
    }

    /// A zero replica count must not divide by zero.
    #[test]
    fn zero_replicas_is_treated_as_one() {
        assert_eq!(replica_share(100, 0, 0), 100);
    }
}

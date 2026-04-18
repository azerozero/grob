//! Passive circuit breaker — RE-1a (Caddy-inspired, ADR-0018).
//!
//! Per-endpoint (provider + model pair) circuit breaker that observes the
//! real traffic and trips when consecutive failures exceed a threshold. It
//! is deliberately *passive* — no background probe, no health check request,
//! no extra load on the upstream. The active probing flavour is tracked as
//! RE-1b (`src/routing/health_check.rs`, to be added in a follow-up PR).
//!
//! # Caddy reference
//!
//! Design follows Caddy's [`reverse_proxy`
//! passive health checks](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy#passive-health-checks):
//!
//! - `max_fails` — how many failures before the endpoint is marked down
//!   (Caddy default: 1, Grob default: 1 to preserve Caddy parity).
//! - `fail_duration` — sliding window during which failures count. After
//!   this duration a recorded failure is decremented back out. Default 0
//!   disables the breaker entirely (opt-in, backward-compatible).
//! - `cooldown` — optional post-trip rest period during which the endpoint
//!   stays down regardless of the counter. Default none (recover immediately
//!   once the failure decays out).
//!
//! # Hot path
//!
//! The hot path — [`CircuitBreaker::is_healthy`] — is a single atomic load
//! plus one `ArcSwap` load. No mutex, no syscall, no heap allocation. The
//! cost of a healthy dispatch is effectively zero.
//!
//! # Failure decay
//!
//! Failures are decremented by a tokio task scheduled at `record_failure`
//! time. The alternative (absolute `tripped_until` timestamp without a
//! background task) was rejected because RE-1a must support an opt-in
//! sliding window independent of the trip — operators want "three
//! failures in 30 seconds trips the breaker", not "three failures ever
//! trips it until a dispatch succeeds".
//!
//! # Observability
//!
//! Every trip and every recovery emits one `info!` line with a clear
//! banner so the event is trivially greppable in production logs. Counter
//! metrics are deferred to RE-2 when the EMA stats module lands.

use arc_swap::ArcSwap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;
use tracing::info;

/// Endpoint identity key: `(provider_name, model_name)` pair.
///
/// Used by higher layers (e.g. provider registry) to index a circuit
/// breaker per physical endpoint. An "endpoint" in ADR-0018 parlance is
/// the `(provider, model)` tuple — the same provider with two different
/// models owns two breakers.
pub type EndpointId = (String, String);

/// Configuration for a per-endpoint passive circuit breaker.
///
/// # Defaults (Caddy parity)
///
/// - `max_fails = 1` — one failure is enough to trip.
/// - `fail_duration = 0` — **disabled**. The breaker never trips.
/// - `cooldown = None` — no post-trip rest.
///
/// The disabled-by-default default is intentional: RE-1a ships as opt-in.
/// A brand-new Grob instance behaves exactly as before this module
/// existed until the operator writes a config section.
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Consecutive failures required to trip the breaker. Caddy default: 1.
    pub max_fails: u32,
    /// Sliding window for failure counting. Zero disables the breaker.
    pub fail_duration: Duration,
    /// Optional post-trip rest period.
    pub cooldown: Option<Duration>,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        // NOTE: Caddy parity — MaxFails=1, FailDuration=0 (disabled).
        Self {
            max_fails: 1,
            fail_duration: Duration::ZERO,
            cooldown: None,
        }
    }
}

impl CircuitBreakerConfig {
    /// Returns `true` when the breaker is effectively disabled.
    ///
    /// A zero `fail_duration` means failures never count against the
    /// endpoint, so the breaker can short-circuit every code path.
    pub fn is_enabled(&self) -> bool {
        !self.fail_duration.is_zero()
    }
}

/// Passive circuit breaker for one endpoint.
///
/// Construct with [`CircuitBreaker::new`], wire it into the provider loop
/// via [`record_success`](Self::record_success),
/// [`record_failure`](Self::record_failure), and
/// [`is_healthy`](Self::is_healthy).
pub struct CircuitBreaker {
    /// Human-readable endpoint tag — used only in log lines.
    label: String,
    config: CircuitBreakerConfig,
    /// Number of failures still inside the sliding window.
    fail_count: AtomicU32,
    /// When present and in the future, the endpoint is in post-trip cooldown.
    tripped_until: ArcSwap<Option<Instant>>,
}

impl CircuitBreaker {
    /// Creates a fresh circuit breaker with the given configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// use grob::routing::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig};
    /// use std::time::Duration;
    ///
    /// let cb = CircuitBreaker::new(
    ///     "anthropic/claude-opus-4-7".to_string(),
    ///     CircuitBreakerConfig {
    ///         max_fails: 3,
    ///         fail_duration: Duration::from_secs(30),
    ///         cooldown: Some(Duration::from_secs(60)),
    ///     },
    /// );
    /// assert!(cb.is_healthy());
    /// ```
    pub fn new(label: String, config: CircuitBreakerConfig) -> Arc<Self> {
        Arc::new(Self {
            label,
            config,
            fail_count: AtomicU32::new(0),
            tripped_until: ArcSwap::from_pointee(None),
        })
    }

    /// Returns the endpoint label used in log lines.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Returns the configuration snapshot.
    pub fn config(&self) -> &CircuitBreakerConfig {
        &self.config
    }

    /// Returns `true` when the endpoint is currently considered usable.
    ///
    /// An endpoint is healthy unless it is in post-trip cooldown.
    pub fn is_healthy(&self) -> bool {
        // Disabled breaker is always healthy — skip even the ArcSwap load.
        if !self.config.is_enabled() {
            return true;
        }
        !matches!(**self.tripped_until.load(), Some(until) if Instant::now() < until)
    }

    /// Records a successful response.
    ///
    /// Resets the failure counter to zero and clears any active cooldown,
    /// restoring the endpoint to the healthy state. Idempotent.
    pub fn record_success(&self) {
        if !self.config.is_enabled() {
            return;
        }
        let prev = self.fail_count.swap(0, Ordering::Relaxed);
        let was_tripped = self.tripped_until.load().is_some();
        if was_tripped {
            self.tripped_until.store(Arc::new(None));
            info!(
                endpoint = %self.label,
                "✅ circuit-breaker RECOVERED for endpoint {}",
                self.label
            );
        } else if prev > 0 {
            tracing::debug!(
                endpoint = %self.label,
                previous_fails = prev,
                "circuit-breaker counter reset after success"
            );
        }
    }

    /// Records a failed response.
    ///
    /// Increments the failure counter. When the counter reaches
    /// `max_fails`, the endpoint is tripped for the cooldown window (or
    /// for `fail_duration` if no cooldown is configured). A tokio task is
    /// scheduled to decrement the counter after `fail_duration` so that
    /// stale failures do not accumulate across the sliding window.
    pub fn record_failure(self: &Arc<Self>) {
        if !self.config.is_enabled() {
            return;
        }

        let new_count = self.fail_count.fetch_add(1, Ordering::Relaxed) + 1;

        if new_count >= self.config.max_fails {
            // NOTE: Only trip if not already tripped — avoids spamming the log on a burst.
            let was_tripped = self.tripped_until.load().is_some();
            if !was_tripped {
                let rest = self.config.cooldown.unwrap_or(self.config.fail_duration);
                let until = Instant::now() + rest;
                self.tripped_until.store(Arc::new(Some(until)));
                info!(
                    endpoint = %self.label,
                    fails = new_count,
                    window_secs = self.config.fail_duration.as_secs(),
                    "🚨 circuit-breaker TRIPPED for endpoint {} ({} fails in {}s)",
                    self.label,
                    new_count,
                    self.config.fail_duration.as_secs()
                );
            }
        }

        // Schedule the decrement after the sliding-window expires.
        // The Arc clone is cheap; the task holds no strong reference beyond its own scope.
        let this = Arc::clone(self);
        let window = self.config.fail_duration;
        tokio::spawn(async move {
            tokio::time::sleep(window).await;
            // Saturating decrement: never underflow if record_success raced us.
            loop {
                let current = this.fail_count.load(Ordering::Relaxed);
                if current == 0 {
                    break;
                }
                if this
                    .fail_count
                    .compare_exchange_weak(
                        current,
                        current - 1,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    )
                    .is_ok()
                {
                    break;
                }
            }
            // Cooldown auto-expires via `is_healthy` timestamp check — no action needed here.
        });
    }

    /// Returns the current failure count (testing / observability hook).
    pub fn fail_count(&self) -> u32 {
        self.fail_count.load(Ordering::Relaxed)
    }

    /// Returns `true` when the endpoint is in post-trip cooldown.
    pub fn is_tripped(&self) -> bool {
        matches!(
            **self.tripped_until.load(),
            Some(until) if Instant::now() < until
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn enabled_cfg(max_fails: u32, fail_duration: Duration) -> CircuitBreakerConfig {
        CircuitBreakerConfig {
            max_fails,
            fail_duration,
            cooldown: None,
        }
    }

    #[tokio::test]
    async fn new_cb_is_healthy() {
        let cb = CircuitBreaker::new("test".into(), enabled_cfg(3, Duration::from_secs(10)));
        assert!(cb.is_healthy());
        assert!(!cb.is_tripped());
        assert_eq!(cb.fail_count(), 0);
    }

    #[tokio::test]
    async fn max_fails_trips_cb() {
        let cb = CircuitBreaker::new(
            "test".into(),
            CircuitBreakerConfig {
                max_fails: 3,
                fail_duration: Duration::from_secs(60),
                cooldown: Some(Duration::from_secs(60)),
            },
        );
        cb.record_failure();
        assert!(cb.is_healthy(), "1 failure below threshold");
        cb.record_failure();
        assert!(cb.is_healthy(), "2 failures still below threshold");
        cb.record_failure();
        assert!(!cb.is_healthy(), "3 failures trip the breaker");
        assert!(cb.is_tripped());
    }

    #[tokio::test]
    async fn success_resets_counter() {
        let cb = CircuitBreaker::new("test".into(), enabled_cfg(3, Duration::from_secs(60)));
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.fail_count(), 2);
        cb.record_success();
        assert_eq!(cb.fail_count(), 0);
        assert!(cb.is_healthy());
    }

    #[tokio::test]
    async fn success_clears_trip_state() {
        let cb = CircuitBreaker::new(
            "test".into(),
            CircuitBreakerConfig {
                max_fails: 1,
                fail_duration: Duration::from_secs(60),
                cooldown: Some(Duration::from_secs(60)),
            },
        );
        cb.record_failure();
        assert!(!cb.is_healthy());
        cb.record_success();
        assert!(cb.is_healthy(), "success must clear an active trip");
        assert!(!cb.is_tripped());
    }

    #[tokio::test(start_paused = true)]
    async fn cooldown_recovery() {
        let cb = CircuitBreaker::new(
            "test".into(),
            CircuitBreakerConfig {
                max_fails: 1,
                // NOTE: fail_duration large so decrement task doesn't interfere with timing.
                fail_duration: Duration::from_secs(3600),
                cooldown: Some(Duration::from_millis(50)),
            },
        );
        cb.record_failure();
        assert!(!cb.is_healthy(), "tripped immediately after 1 failure");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(cb.is_healthy(), "breaker recovers after cooldown expires");
    }

    #[tokio::test(start_paused = true)]
    async fn fail_duration_decrement() {
        let cb = CircuitBreaker::new("test".into(), enabled_cfg(3, Duration::from_millis(100)));
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.fail_count(), 2);
        // Advance the mocked clock past fail_duration so the decrement tasks fire.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            cb.fail_count(),
            0,
            "both scheduled decrement tasks must have run"
        );
    }

    #[tokio::test]
    async fn disabled_cb_never_trips() {
        // fail_duration = 0 means disabled (Caddy default).
        let cb = CircuitBreaker::new("test".into(), CircuitBreakerConfig::default());
        assert!(!cb.config().is_enabled());
        for _ in 0..100 {
            cb.record_failure();
        }
        assert!(cb.is_healthy(), "disabled breaker stays healthy forever");
        assert_eq!(
            cb.fail_count(),
            0,
            "disabled breaker does not even count failures"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn trip_then_fail_duration_expires_without_cooldown() {
        // Without explicit cooldown, `rest` == `fail_duration`.
        let cb = CircuitBreaker::new("test".into(), enabled_cfg(1, Duration::from_millis(50)));
        cb.record_failure();
        assert!(!cb.is_healthy(), "tripped on first failure");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            cb.is_healthy(),
            "breaker recovers once the trip window expires"
        );
    }

    #[tokio::test]
    async fn concurrent_failures_trip_once() {
        // Hammer the breaker from many tasks; only one trip log should fire.
        let cb = CircuitBreaker::new(
            "test".into(),
            CircuitBreakerConfig {
                max_fails: 5,
                fail_duration: Duration::from_secs(60),
                cooldown: Some(Duration::from_secs(60)),
            },
        );
        let mut handles = Vec::new();
        for _ in 0..32 {
            let cb = Arc::clone(&cb);
            handles.push(tokio::spawn(async move {
                cb.record_failure();
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert!(!cb.is_healthy());
        assert!(cb.fail_count() >= 5);
    }
}

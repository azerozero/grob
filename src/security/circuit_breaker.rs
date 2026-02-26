//! Circuit breaker pattern for provider resilience
//! Implements PCA/PRA requirements for HDS/PCI/SecNumCloud
//!
//! States:
//! - Closed: Normal operation, requests pass through
//! - Open: Failure threshold reached, requests fail fast
//! - HalfOpen: Testing if service recovered

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Circuit breaker state
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

/// Circuit breaker configuration
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Failure threshold to open circuit
    pub failure_threshold: u32,
    /// Success threshold to close circuit from half-open
    pub success_threshold: u32,
    /// Timeout before attempting half-open
    pub timeout: Duration,
    /// Half-open max requests
    pub half_open_max_calls: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            success_threshold: 3,
            timeout: Duration::from_secs(30),
            half_open_max_calls: 3,
        }
    }
}

/// Circuit breaker metrics
#[derive(Debug, Clone, Default)]
struct CircuitMetrics {
    failures: u32,
    successes: u32,
    consecutive_successes: u32,
    consecutive_failures: u32,
    last_failure_time: Option<Instant>,
    state_changes: u32,
}

/// Individual circuit breaker for a provider
#[derive(Debug)]
struct CircuitBreaker {
    name: String,
    state: CircuitState,
    config: CircuitBreakerConfig,
    metrics: CircuitMetrics,
    last_state_change: Instant,
    half_open_calls: u32,
}

impl CircuitBreaker {
    fn new(name: String, config: CircuitBreakerConfig) -> Self {
        Self {
            name,
            state: CircuitState::Closed,
            config,
            metrics: CircuitMetrics::default(),
            last_state_change: Instant::now(),
            half_open_calls: 0,
        }
    }

    /// Check if request should be allowed
    fn can_execute(&mut self) -> bool {
        match self.state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                // Check if timeout elapsed
                if self.last_state_change.elapsed() >= self.config.timeout {
                    self.transition_to(CircuitState::HalfOpen);
                    true
                } else {
                    false
                }
            }
            CircuitState::HalfOpen => {
                if self.half_open_calls < self.config.half_open_max_calls {
                    self.half_open_calls += 1;
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Record successful execution
    fn record_success(&mut self) {
        self.metrics.successes += 1;
        self.metrics.consecutive_successes += 1;
        self.metrics.consecutive_failures = 0;

        match self.state {
            CircuitState::HalfOpen => {
                if self.metrics.consecutive_successes >= self.config.success_threshold {
                    self.transition_to(CircuitState::Closed);
                }
            }
            CircuitState::Closed => {
                // Reset consecutive failures tracking
            }
            _ => {}
        }
    }

    /// Record failed execution
    fn record_failure(&mut self) {
        self.metrics.failures += 1;
        self.metrics.consecutive_failures += 1;
        self.metrics.consecutive_successes = 0;
        self.metrics.last_failure_time = Some(Instant::now());

        match self.state {
            CircuitState::Closed => {
                if self.metrics.consecutive_failures >= self.config.failure_threshold {
                    self.transition_to(CircuitState::Open);
                }
            }
            CircuitState::HalfOpen => {
                self.transition_to(CircuitState::Open);
            }
            _ => {}
        }
    }

    /// Get current state
    fn state(&self) -> CircuitState {
        self.state
    }

    /// Transition to new state
    fn transition_to(&mut self, new_state: CircuitState) {
        if self.state != new_state {
            tracing::info!(
                "Circuit breaker '{}' transitioning {:?} -> {:?}",
                self.name,
                self.state,
                new_state
            );

            self.state = new_state;
            self.last_state_change = Instant::now();
            self.metrics.state_changes += 1;
            self.half_open_calls = 0;
            self.metrics.consecutive_successes = 0;
            self.metrics.consecutive_failures = 0;

            // Emit metric
            metrics::gauge!(
                "grob_circuit_breaker_state",
                "provider" => self.name.clone()
            )
            .set(match new_state {
                CircuitState::Closed => 0.0,
                CircuitState::Open => 1.0,
                CircuitState::HalfOpen => 2.0,
            });
        }
    }
}

/// Circuit breaker registry for multiple providers
pub struct CircuitBreakerRegistry {
    breakers: Arc<RwLock<HashMap<String, CircuitBreaker>>>,
    default_config: CircuitBreakerConfig,
}

impl CircuitBreakerRegistry {
    pub fn new() -> Self {
        Self::with_config(CircuitBreakerConfig::default())
    }

    fn with_config(config: CircuitBreakerConfig) -> Self {
        Self {
            breakers: Arc::new(RwLock::new(HashMap::new())),
            default_config: config,
        }
    }

    /// Check if provider can execute
    pub async fn can_execute(&self, provider: &str) -> bool {
        let mut breakers = self.breakers.write().await;

        let breaker = breakers
            .entry(provider.to_string())
            .or_insert_with(|| CircuitBreaker::new(provider.to_string(), self.default_config.clone()));

        breaker.can_execute()
    }

    /// Record success for provider
    pub async fn record_success(&self, provider: &str) {
        let mut breakers = self.breakers.write().await;

        let breaker = breakers
            .entry(provider.to_string())
            .or_insert_with(|| CircuitBreaker::new(provider.to_string(), self.default_config.clone()));

        breaker.record_success();
    }

    /// Record failure for provider
    pub async fn record_failure(&self, provider: &str) {
        let mut breakers = self.breakers.write().await;

        let breaker = breakers
            .entry(provider.to_string())
            .or_insert_with(|| CircuitBreaker::new(provider.to_string(), self.default_config.clone()));

        breaker.record_failure();
    }

    /// Get all provider states
    pub async fn all_states(&self) -> HashMap<String, CircuitState> {
        let breakers = self.breakers.read().await;
        breakers
            .iter()
            .map(|(k, v)| (k.clone(), v.state()))
            .collect()
    }
}

impl Default for CircuitBreakerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;

    #[test]
    fn test_circuit_breaker_new() {
        let cb = CircuitBreaker::new("test".to_string(), CircuitBreakerConfig::default());
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn test_circuit_breaker_success() {
        let mut cb = CircuitBreaker::new("test".to_string(), CircuitBreakerConfig::default());

        assert!(cb.can_execute());
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn test_circuit_breaker_failure_threshold() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            ..Default::default()
        };
        let mut cb = CircuitBreaker::new("test".to_string(), config);

        // Record failures
        for _ in 0..3 {
            assert!(cb.can_execute());
            cb.record_failure();
        }

        // Circuit should be open
        assert_eq!(cb.state(), CircuitState::Open);
        assert!(!cb.can_execute());
    }

    #[tokio::test]
    async fn test_circuit_breaker_recovery() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            success_threshold: 2,
            timeout: Duration::from_millis(100),
            half_open_max_calls: 3,
        };
        let mut cb = CircuitBreaker::new("test".to_string(), config);

        // Open the circuit
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);

        // Wait for timeout
        sleep(Duration::from_millis(150)).await;

        // Should transition to half-open
        assert!(cb.can_execute());
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        // Record successes to close
        cb.record_success();
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[tokio::test]
    async fn test_registry() {
        let registry = CircuitBreakerRegistry::new();

        // Initially closed
        assert!(registry.can_execute("provider1").await);

        // Record failures
        registry.record_failure("provider1").await;
        registry.record_failure("provider1").await;
        registry.record_failure("provider1").await;
        registry.record_failure("provider1").await;
        registry.record_failure("provider1").await;

        // Circuit should be open
        assert!(!registry.can_execute("provider1").await);

        // Verify via all_states
        let states = registry.all_states().await;
        assert_eq!(states.get("provider1"), Some(&CircuitState::Open));

        // Other providers not affected
        assert!(registry.can_execute("provider2").await);
    }
}

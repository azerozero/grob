//! Adaptive provider scoring with composite quality metric.
//!
//! Computes `success_rate × latency_factor × confidence` per provider and
//! integrates with the circuit breaker to override scores when circuits are
//! open or half-open.

use crate::cli::ModelMapping;
use crate::security::circuit_breaker::{CircuitBreakerRegistry, CircuitState};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

/// Scoring algorithm configuration.
#[derive(Debug, Clone)]
pub struct ScorerConfig {
    /// EWMA alpha for latency smoothing (0.0–1.0).
    pub latency_alpha: f64,
    /// Rolling window size for success rate.
    pub window_size: usize,
    /// Decay rate per second of inactivity.
    pub decay_rate: f64,
}

impl Default for ScorerConfig {
    fn default() -> Self {
        Self {
            latency_alpha: 0.3,
            window_size: 50,
            decay_rate: 0.001,
        }
    }
}

/// Per-provider score state.
#[derive(Debug, Clone)]
struct ProviderScore {
    /// Circular buffer of outcomes (true = success).
    outcomes: Vec<bool>,
    /// Write index into the circular buffer.
    write_idx: usize,
    /// Number of recorded outcomes (capped at window_size).
    count: usize,
    /// EWMA of latency in milliseconds.
    latency_ewma: f64,
    /// Timestamp of the last recorded event.
    last_used: Instant,
}

impl ProviderScore {
    fn new(window_size: usize) -> Self {
        Self {
            outcomes: vec![false; window_size],
            write_idx: 0,
            count: 0,
            latency_ewma: 0.0,
            last_used: Instant::now(),
        }
    }

    fn push_outcome(&mut self, success: bool) {
        self.outcomes[self.write_idx] = success;
        self.write_idx = (self.write_idx + 1) % self.outcomes.len();
        if self.count < self.outcomes.len() {
            self.count += 1;
        }
        self.last_used = Instant::now();
    }

    fn success_rate(&self) -> f64 {
        if self.count == 0 {
            return 1.0;
        }
        let successes = if self.count < self.outcomes.len() {
            self.outcomes[..self.count].iter().filter(|&&s| s).count()
        } else {
            self.outcomes.iter().filter(|&&s| s).count()
        };
        successes as f64 / self.count as f64
    }

    fn update_latency(&mut self, latency_ms: u64, alpha: f64) {
        let ms = latency_ms as f64;
        if self.latency_ewma == 0.0 {
            self.latency_ewma = ms;
        } else {
            self.latency_ewma = alpha * ms + (1.0 - alpha) * self.latency_ewma;
        }
    }

    fn latency_factor(&self) -> f64 {
        1.0 / (1.0 + self.latency_ewma / 1000.0)
    }

    fn confidence(&self, decay_rate: f64) -> f64 {
        let secs = self.last_used.elapsed().as_secs_f64();
        (1.0 - decay_rate * secs).max(0.3)
    }

    fn composite(&self, decay_rate: f64) -> f64 {
        self.success_rate() * self.latency_factor() * self.confidence(decay_rate)
    }
}

/// Adaptive provider scorer with optional circuit breaker integration.
pub struct ProviderScorer {
    config: ScorerConfig,
    scores: Arc<RwLock<HashMap<String, ProviderScore>>>,
    circuit_breakers: Option<Arc<CircuitBreakerRegistry>>,
}

impl ProviderScorer {
    /// Creates a new scorer with optional circuit breaker integration.
    pub fn new(
        config: ScorerConfig,
        circuit_breakers: Option<Arc<CircuitBreakerRegistry>>,
    ) -> Self {
        Self {
            config,
            scores: Arc::new(RwLock::new(HashMap::new())),
            circuit_breakers,
        }
    }

    /// Records a successful request with latency.
    pub async fn record_success(&self, provider: &str, latency_ms: u64) {
        let mut scores = self.scores.write().await;
        let score = scores
            .entry(provider.to_string())
            .or_insert_with(|| ProviderScore::new(self.config.window_size));
        score.push_outcome(true);
        score.update_latency(latency_ms, self.config.latency_alpha);

        // Also forward to circuit breaker
        if let Some(ref cb) = self.circuit_breakers {
            cb.record_success(provider).await;
        }
    }

    /// Records a failed request.
    pub async fn record_failure(&self, provider: &str) {
        let mut scores = self.scores.write().await;
        let score = scores
            .entry(provider.to_string())
            .or_insert_with(|| ProviderScore::new(self.config.window_size));
        score.push_outcome(false);

        // Also forward to circuit breaker
        if let Some(ref cb) = self.circuit_breakers {
            cb.record_failure(provider).await;
        }
    }

    /// Returns the adaptive factor for a provider (0.0–1.0).
    ///
    /// Integrates circuit breaker state: Open → 0.0, HalfOpen → capped at 0.1.
    pub async fn adaptive_factor(&self, provider: &str) -> f64 {
        // Circuit breaker override
        if let Some(ref cb) = self.circuit_breakers {
            let states = cb.all_states().await;
            if let Some(state) = states.get(provider) {
                match state {
                    CircuitState::Open => return 0.0,
                    CircuitState::HalfOpen => {
                        let raw = self.raw_score(provider).await;
                        return raw.min(0.1);
                    }
                    CircuitState::Closed => {}
                }
            }
        }

        self.raw_score(provider).await
    }

    /// Returns the raw composite score without circuit breaker overlay.
    async fn raw_score(&self, provider: &str) -> f64 {
        let scores = self.scores.read().await;
        scores
            .get(provider)
            .map(|s| s.composite(self.config.decay_rate))
            .unwrap_or(1.0)
    }

    /// Re-sorts model mappings by `priority / adaptive_factor`.
    ///
    /// Lower effective priority = tried first. Providers with factor 0.0 are
    /// pushed to the end (infinite effective priority).
    pub async fn sort_mappings(&self, mut mappings: Vec<ModelMapping>) -> Vec<ModelMapping> {
        let mut scored: Vec<(f64, usize)> = Vec::with_capacity(mappings.len());
        for (i, m) in mappings.iter().enumerate() {
            let factor = self.adaptive_factor(&m.provider).await;
            let effective = if factor > 0.0 {
                m.priority as f64 / factor
            } else {
                f64::MAX
            };
            scored.push((effective, i));
        }
        scored.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));

        let order: Vec<usize> = scored.iter().map(|&(_, i)| i).collect();
        let mut sorted = Vec::with_capacity(mappings.len());
        for idx in order {
            // Swap with a dummy to avoid clone
            sorted.push(std::mem::replace(
                &mut mappings[idx],
                ModelMapping {
                    priority: 0,
                    provider: String::new(),
                    actual_model: String::new(),
                    inject_continuation_prompt: false,
                },
            ));
        }
        sorted
    }

    /// Returns all current scores for debugging.
    pub async fn all_scores(&self) -> HashMap<String, f64> {
        let scores = self.scores.read().await;
        scores
            .iter()
            .map(|(k, v)| (k.clone(), v.composite(self.config.decay_rate)))
            .collect()
    }

    /// Returns detailed score components for metrics.
    pub async fn all_score_details(&self) -> HashMap<String, (f64, f64, f64)> {
        let scores = self.scores.read().await;
        scores
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    (
                        v.success_rate(),
                        v.latency_ewma,
                        v.composite(self.config.decay_rate),
                    ),
                )
            })
            .collect()
    }

    /// Checks if a provider can accept requests (delegates to circuit breaker).
    pub async fn can_execute(&self, provider: &str) -> bool {
        if let Some(ref cb) = self.circuit_breakers {
            cb.can_execute(provider).await
        } else {
            true
        }
    }
}

// ── Trait implementation ──

#[async_trait::async_trait]
impl crate::traits::ProviderAvailability for ProviderScorer {
    async fn can_execute(&self, provider: &str) -> bool {
        self.can_execute(provider).await
    }

    async fn record_success(&self, provider: &str) {
        // Record with 0 latency when called through the trait (latency unknown).
        // The dispatch layer should call record_success(provider, latency_ms) directly.
        self.record_success(provider, 0).await;
    }

    async fn record_failure(&self, provider: &str) {
        self.record_failure(provider).await;
    }

    async fn all_states(&self) -> HashMap<String, CircuitState> {
        if let Some(ref cb) = self.circuit_breakers {
            cb.all_states().await
        } else {
            HashMap::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> ScorerConfig {
        ScorerConfig {
            latency_alpha: 0.3,
            window_size: 5,
            decay_rate: 0.001,
        }
    }

    #[tokio::test]
    async fn test_new_provider_has_full_score() {
        let scorer = ProviderScorer::new(test_config(), None);
        let factor = scorer.adaptive_factor("unknown_provider").await;
        assert!((factor - 1.0).abs() < 0.01);
    }

    #[tokio::test]
    async fn test_success_rate_tracking() {
        let scorer = ProviderScorer::new(test_config(), None);

        // 3 successes, 2 failures → 60% success rate
        scorer.record_success("p1", 100).await;
        scorer.record_success("p1", 100).await;
        scorer.record_success("p1", 100).await;
        scorer.record_failure("p1").await;
        scorer.record_failure("p1").await;

        let scores = scorer.scores.read().await;
        let s = scores.get("p1").unwrap();
        assert!((s.success_rate() - 0.6).abs() < 0.01);
    }

    #[tokio::test]
    async fn test_latency_ewma() {
        let scorer = ProviderScorer::new(test_config(), None);

        scorer.record_success("p1", 100).await;
        let scores = scorer.scores.read().await;
        assert!((scores.get("p1").unwrap().latency_ewma - 100.0).abs() < 0.01);
        drop(scores);

        scorer.record_success("p1", 200).await;
        let scores = scorer.scores.read().await;
        // EWMA: 0.3 * 200 + 0.7 * 100 = 130
        assert!((scores.get("p1").unwrap().latency_ewma - 130.0).abs() < 0.01);
    }

    #[tokio::test]
    async fn test_all_failures_low_score() {
        let scorer = ProviderScorer::new(test_config(), None);

        for _ in 0..5 {
            scorer.record_failure("bad_provider").await;
        }

        let factor = scorer.adaptive_factor("bad_provider").await;
        assert!(factor < 0.05, "Expected near-zero score, got {}", factor);
    }

    #[tokio::test]
    async fn test_sort_mappings_prefers_better_provider() {
        let scorer = ProviderScorer::new(test_config(), None);

        // p_good: 5 successes with low latency
        for _ in 0..5 {
            scorer.record_success("p_good", 50).await;
        }
        // p_bad: 5 failures
        for _ in 0..5 {
            scorer.record_failure("p_bad").await;
        }

        let mappings = vec![
            ModelMapping {
                priority: 1,
                provider: "p_bad".to_string(),
                actual_model: "model-a".to_string(),
                inject_continuation_prompt: false,
            },
            ModelMapping {
                priority: 2,
                provider: "p_good".to_string(),
                actual_model: "model-b".to_string(),
                inject_continuation_prompt: false,
            },
        ];

        let sorted = scorer.sort_mappings(mappings).await;
        assert_eq!(sorted[0].provider, "p_good");
        assert_eq!(sorted[1].provider, "p_bad");
    }

    #[tokio::test]
    async fn test_circuit_breaker_open_yields_zero() {
        let cb = Arc::new(CircuitBreakerRegistry::new());

        // Open the circuit (5 consecutive failures with default threshold)
        for _ in 0..5 {
            cb.record_failure("broken").await;
        }

        let scorer = ProviderScorer::new(test_config(), Some(cb));
        let factor = scorer.adaptive_factor("broken").await;
        assert!(
            (factor - 0.0).abs() < 0.001,
            "Open circuit should yield 0.0, got {}",
            factor
        );
    }

    #[tokio::test]
    async fn test_rolling_window_circular() {
        let config = ScorerConfig {
            window_size: 3,
            ..test_config()
        };
        let scorer = ProviderScorer::new(config, None);

        // Fill window with failures
        scorer.record_failure("p1").await;
        scorer.record_failure("p1").await;
        scorer.record_failure("p1").await;

        let scores = scorer.scores.read().await;
        assert!((scores.get("p1").unwrap().success_rate() - 0.0).abs() < 0.01);
        drop(scores);

        // Now add 3 successes, overwriting the failures
        scorer.record_success("p1", 100).await;
        scorer.record_success("p1", 100).await;
        scorer.record_success("p1", 100).await;

        let scores = scorer.scores.read().await;
        assert!((scores.get("p1").unwrap().success_rate() - 1.0).abs() < 0.01);
    }
}

//! EWMA-based tool scoring per (tool, provider, metric) triple.
//!
//! Follows the same circular-buffer + EWMA pattern as
//! [`crate::security::provider_scorer::ProviderScorer`], scoped to individual
//! tool-calling metrics.

use super::matrix::{RUNTIME_BLEND_WEIGHT, STATIC_BLEND_WEIGHT};
use std::collections::HashMap;
use std::time::Instant;

/// Benchmark metrics for evaluating tool-calling quality per provider.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub enum ToolMetric {
    /// Model selects the correct tool from the list.
    ToolSelectionAccuracy,
    /// Generated parameters are valid JSON Schema.
    ParamValidity,
    /// All required fields are present.
    ParamCompliance,
    /// `tool_choice: {name: "X"}` is respected.
    ToolChoiceRespect,
    /// Model can emit >1 tool_use in a single turn.
    ParallelToolSupport,
    /// Model continues correctly after receiving a tool_result.
    ToolResultHandling,
}

impl std::fmt::Display for ToolMetric {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl ToolMetric {
    /// Returns all metric variants for iteration.
    pub fn all() -> &'static [ToolMetric] {
        &[
            ToolMetric::ToolSelectionAccuracy,
            ToolMetric::ParamValidity,
            ToolMetric::ParamCompliance,
            ToolMetric::ToolChoiceRespect,
            ToolMetric::ParallelToolSupport,
            ToolMetric::ToolResultHandling,
        ]
    }

    /// Returns the string key for serialization.
    pub fn as_str(&self) -> &'static str {
        match self {
            ToolMetric::ToolSelectionAccuracy => "tool_selection_accuracy",
            ToolMetric::ParamValidity => "param_validity",
            ToolMetric::ParamCompliance => "param_compliance",
            ToolMetric::ToolChoiceRespect => "tool_choice_respect",
            ToolMetric::ParallelToolSupport => "parallel_tool_support",
            ToolMetric::ToolResultHandling => "tool_result_handling",
        }
    }

    /// Default weight for the composite score computation.
    ///
    /// Weights reflect production impact: tool selection and parameter correctness
    /// (0.25 + 0.20 + 0.20 = 0.65) dominate because wrong tools or bad params
    /// cause request failures. Protocol features (choice respect, parallel, result
    /// handling) are secondary at 0.15 + 0.10 + 0.10 = 0.35. Weights sum to 1.0.
    pub fn weight(&self) -> f64 {
        match self {
            ToolMetric::ToolSelectionAccuracy => WEIGHT_TOOL_SELECTION,
            ToolMetric::ParamValidity => WEIGHT_PARAM_VALIDITY,
            ToolMetric::ParamCompliance => WEIGHT_PARAM_COMPLIANCE,
            ToolMetric::ToolChoiceRespect => WEIGHT_TOOL_CHOICE_RESPECT,
            ToolMetric::ParallelToolSupport => WEIGHT_PARALLEL_SUPPORT,
            ToolMetric::ToolResultHandling => WEIGHT_RESULT_HANDLING,
        }
    }
}

/// Weight for tool selection accuracy metric.
const WEIGHT_TOOL_SELECTION: f64 = 0.25;
/// Weight for parameter validity metric.
const WEIGHT_PARAM_VALIDITY: f64 = 0.20;
/// Weight for parameter compliance metric.
const WEIGHT_PARAM_COMPLIANCE: f64 = 0.20;
/// Weight for tool choice respect metric.
const WEIGHT_TOOL_CHOICE_RESPECT: f64 = 0.15;
/// Weight for parallel tool support metric.
const WEIGHT_PARALLEL_SUPPORT: f64 = 0.10;
/// Weight for tool result handling metric.
const WEIGHT_RESULT_HANDLING: f64 = 0.10;

/// Per-metric rolling score state.
#[derive(Debug, Clone)]
struct MetricScore {
    outcomes: Vec<bool>,
    write_idx: usize,
    count: usize,
    last_used: Instant,
}

impl MetricScore {
    fn new(window_size: usize) -> Self {
        Self {
            outcomes: vec![false; window_size],
            write_idx: 0,
            count: 0,
            last_used: Instant::now(),
        }
    }

    fn push(&mut self, success: bool) {
        self.outcomes[self.write_idx] = success;
        self.write_idx = (self.write_idx + 1) % self.outcomes.len();
        if self.count < self.outcomes.len() {
            self.count += 1;
        }
        self.last_used = Instant::now();
    }

    fn success_rate(&self) -> f64 {
        if self.count == 0 {
            // Optimistic default: unseen metrics assumed successful until proven otherwise.
            return 1.0;
        }
        let successes = if self.count < self.outcomes.len() {
            self.outcomes[..self.count].iter().filter(|&&s| s).count()
        } else {
            self.outcomes.iter().filter(|&&s| s).count()
        };
        successes as f64 / self.count as f64
    }
}

/// Tool-calling scorer with EWMA + circular buffer per (tool, provider, metric).
#[derive(Debug)]
pub struct ToolScorer {
    window_size: usize,
    scores: HashMap<String, HashMap<String, HashMap<ToolMetric, MetricScore>>>,
}

impl ToolScorer {
    /// Creates a new scorer with the given rolling window size.
    pub fn new(window_size: usize) -> Self {
        Self {
            window_size,
            scores: HashMap::new(),
        }
    }

    /// Records a metric outcome for a (tool, provider, metric) triple.
    pub fn record(&mut self, tool: &str, provider: &str, metric: ToolMetric, success: bool) {
        let window_size = self.window_size;
        let entry = self
            .scores
            .entry(tool.to_string())
            .or_default()
            .entry(provider.to_string())
            .or_default()
            .entry(metric)
            .or_insert_with(|| MetricScore::new(window_size));
        entry.push(success);
    }

    /// Returns the success rate for a specific (tool, provider, metric).
    pub fn metric_score(&self, tool: &str, provider: &str, metric: ToolMetric) -> f64 {
        self.scores
            .get(tool)
            .and_then(|providers| providers.get(provider))
            .and_then(|metrics| metrics.get(&metric))
            .map(|s| s.success_rate())
            .unwrap_or(1.0)
    }

    /// Computes the weighted composite score for a (tool, provider) pair.
    ///
    /// Blends the 6 metric scores using their default weights. If `static_reliability`
    /// is provided, mixes 40% static + 60% dynamic.
    pub fn composite_score(
        &self,
        tool: &str,
        provider: &str,
        static_reliability: Option<f64>,
    ) -> f64 {
        let dynamic: f64 = ToolMetric::all()
            .iter()
            .map(|m| m.weight() * self.metric_score(tool, provider, *m))
            .sum();

        match static_reliability {
            Some(sr) => STATIC_BLEND_WEIGHT * sr + RUNTIME_BLEND_WEIGHT * dynamic,
            None => dynamic,
        }
    }

    /// Returns all per-metric scores as a HashMap for a (tool, provider) pair.
    pub fn metric_breakdown(&self, tool: &str, provider: &str) -> HashMap<String, f64> {
        ToolMetric::all()
            .iter()
            .map(|m| {
                (
                    m.as_str().to_string(),
                    self.metric_score(tool, provider, *m),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_metric_defaults_to_one() {
        let scorer = ToolScorer::new(10);
        let score = scorer.metric_score("tool", "provider", ToolMetric::ParamValidity);
        assert!((score - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_record_success_rate() {
        let mut scorer = ToolScorer::new(5);
        scorer.record("t", "p", ToolMetric::ParamValidity, true);
        scorer.record("t", "p", ToolMetric::ParamValidity, true);
        scorer.record("t", "p", ToolMetric::ParamValidity, false);

        let rate = scorer.metric_score("t", "p", ToolMetric::ParamValidity);
        assert!((rate - 2.0 / 3.0).abs() < 0.01);
    }

    #[test]
    fn test_circular_buffer_overwrites() {
        let mut scorer = ToolScorer::new(3);
        // Fill with failures
        for _ in 0..3 {
            scorer.record("t", "p", ToolMetric::ToolSelectionAccuracy, false);
        }
        assert!(scorer.metric_score("t", "p", ToolMetric::ToolSelectionAccuracy) < 0.01);

        // Overwrite with successes
        for _ in 0..3 {
            scorer.record("t", "p", ToolMetric::ToolSelectionAccuracy, true);
        }
        assert!(
            (scorer.metric_score("t", "p", ToolMetric::ToolSelectionAccuracy) - 1.0).abs() < 0.01
        );
    }

    #[test]
    fn test_composite_score_dynamic_only() {
        let mut scorer = ToolScorer::new(10);
        // All metrics succeed
        for m in ToolMetric::all() {
            scorer.record("t", "p", *m, true);
        }
        let composite = scorer.composite_score("t", "p", None);
        assert!((composite - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_composite_score_with_static() {
        let mut scorer = ToolScorer::new(10);
        for m in ToolMetric::all() {
            scorer.record("t", "p", *m, true);
        }
        // 0.4 * 0.8 + 0.6 * 1.0 = 0.92
        let composite = scorer.composite_score("t", "p", Some(0.8));
        assert!((composite - 0.92).abs() < 0.01);
    }

    #[test]
    fn test_metric_breakdown() {
        let scorer = ToolScorer::new(10);
        let breakdown = scorer.metric_breakdown("t", "p");
        assert_eq!(breakdown.len(), 6);
        assert!(breakdown.contains_key("param_validity"));
    }

    #[test]
    fn test_weights_sum_to_one() {
        let total: f64 = ToolMetric::all().iter().map(|m| m.weight()).sum();
        assert!((total - 1.0).abs() < f64::EPSILON);
    }
}

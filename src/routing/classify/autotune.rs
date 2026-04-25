//! Offline auto-tuning helper for the complexity classifier.
//!
//! Pairs with the `grob_autotune` MCP tool. Two modes:
//!
//! - **suggest** — returns the current classifier weights and thresholds as
//!   [`TuneSuggestion`] entries. The MVP does not yet infer patches from
//!   observed traffic, so `proposed == current` and the rationale points
//!   the operator at the manual tuning guide.
//! - **apply** — accepts a list of [`AutotunePatch`] entries and applies
//!   them via the existing `grob_configure` pipeline. This is sugar over
//!   batching multiple `grob_configure update` calls into one MCP round-trip.
//!
//! See `docs/how-to/auto-tune-routing.md` for the recommended workflow.

use serde::{Deserialize, Serialize};

use super::ScoringConfig;

/// A single tuning suggestion for the classifier scoring config.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TuneSuggestion {
    /// Whitelisted classifier key (e.g. `weights.tools`, `thresholds.medium_threshold`).
    pub key: String,
    /// Current value in the running config.
    pub current: f32,
    /// Suggested value (equal to `current` for the MVP no-op autotune).
    pub proposed: f32,
    /// Human-readable explanation for the suggestion (or its absence).
    pub rationale: String,
}

/// Operator-supplied patch consumed by `grob_autotune action=apply`.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct AutotunePatch {
    /// Whitelisted classifier key (same set as `grob_configure section=classifier`).
    pub key: String,
    /// New value (f32, accepted as JSON number).
    pub value: f32,
}

/// Returns the current classifier values as a vector of suggestions.
///
/// Each weight and threshold is reported with `proposed == current` and a
/// rationale that asks the operator to tune manually. Future revisions
/// will replace this with inference from trace data and observed metrics.
pub fn current_snapshot(config: &ScoringConfig) -> Vec<TuneSuggestion> {
    let rationale = "current value; manual tuning recommended (see auto-tune-routing.md)";

    vec![
        TuneSuggestion {
            key: "weights.max_tokens".into(),
            current: config.weights.max_tokens,
            proposed: config.weights.max_tokens,
            rationale: rationale.into(),
        },
        TuneSuggestion {
            key: "weights.tools".into(),
            current: config.weights.tools,
            proposed: config.weights.tools,
            rationale: rationale.into(),
        },
        TuneSuggestion {
            key: "weights.context_size".into(),
            current: config.weights.context_size,
            proposed: config.weights.context_size,
            rationale: rationale.into(),
        },
        TuneSuggestion {
            key: "weights.keywords".into(),
            current: config.weights.keywords,
            proposed: config.weights.keywords,
            rationale: rationale.into(),
        },
        TuneSuggestion {
            key: "weights.system_prompt".into(),
            current: config.weights.system_prompt,
            proposed: config.weights.system_prompt,
            rationale: rationale.into(),
        },
        TuneSuggestion {
            key: "thresholds.medium_threshold".into(),
            current: config.thresholds.medium_threshold,
            proposed: config.thresholds.medium_threshold,
            rationale: rationale.into(),
        },
        TuneSuggestion {
            key: "thresholds.complex_threshold".into(),
            current: config.thresholds.complex_threshold,
            proposed: config.thresholds.complex_threshold,
            rationale: rationale.into(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_reports_all_seven_keys() {
        let cfg = ScoringConfig::default();
        let snapshot = current_snapshot(&cfg);
        assert_eq!(snapshot.len(), 7);
    }

    #[test]
    fn snapshot_proposed_equals_current_in_mvp() {
        let cfg = ScoringConfig::default();
        for entry in current_snapshot(&cfg) {
            assert_eq!(
                entry.proposed, entry.current,
                "MVP autotune must not propose patches"
            );
        }
    }

    #[test]
    fn snapshot_uses_running_values_not_defaults() {
        let mut cfg = ScoringConfig::default();
        cfg.weights.tools = 7.5;
        cfg.thresholds.complex_threshold = 9.0;
        let snapshot = current_snapshot(&cfg);

        let tools = snapshot.iter().find(|s| s.key == "weights.tools").unwrap();
        assert_eq!(tools.current, 7.5);

        let complex = snapshot
            .iter()
            .find(|s| s.key == "thresholds.complex_threshold")
            .unwrap();
        assert_eq!(complex.current, 9.0);
    }

    #[test]
    fn patch_deserialises_from_json() {
        let json = r#"{"key":"weights.tools","value":4.5}"#;
        let p: AutotunePatch = serde_json::from_str(json).unwrap();
        assert_eq!(p.key, "weights.tools");
        assert_eq!(p.value, 4.5);
    }
}

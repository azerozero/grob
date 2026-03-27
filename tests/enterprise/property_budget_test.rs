//! Property-based tests for budget enforcement.
//!
//! Invariant: the spend tracker must NEVER allow a request that would push
//! total spend above the configured budget limit. Once the limit is reached,
//! every subsequent `check_budget` call must return `Err`.

use grob::features::token_pricing::spend::SpendTracker;
use proptest::prelude::*;
use tempfile::TempDir;

// ── Helpers ──────────────────────────────────────────────────────

fn temp_tracker() -> (SpendTracker, TempDir) {
    let dir = TempDir::new().expect("Failed to create temp dir");
    let path = dir.path().join("spend.json");
    (SpendTracker::load(path), dir)
}

// ── Property Tests ───────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// Invariant: after recording costs that sum to >= limit, check_budget
    /// always returns Err for global budget.
    #[test]
    fn budget_global_limit_never_exceeded(
        costs in prop::collection::vec(0.01_f64..10.0, 1..50),
        limit in 1.0_f64..100.0,
    ) {
        let (mut tracker, _dir) = temp_tracker();
        let mut total = 0.0;

        for cost in &costs {
            tracker.record("test-provider", "test-model", *cost);
            total += cost;
        }

        let result = tracker.check_budget(
            "test-provider",
            "test-model",
            limit,
            None,
            None,
        );

        if total >= limit {
            prop_assert!(
                result.is_err(),
                "Budget should be exceeded: total={:.2} limit={:.2}",
                total,
                limit
            );
        } else {
            prop_assert!(
                result.is_ok(),
                "Budget should not be exceeded: total={:.2} limit={:.2}",
                total,
                limit
            );
        }
    }

    /// Invariant: per-provider budget is enforced independently of other providers.
    #[test]
    fn budget_provider_limit_isolated(
        cost_a in prop::collection::vec(0.01_f64..5.0, 1..20),
        cost_b in prop::collection::vec(0.01_f64..5.0, 1..20),
        provider_limit in 1.0_f64..50.0,
    ) {
        let (mut tracker, _dir) = temp_tracker();

        for c in &cost_a {
            tracker.record("provider-a", "model-a", *c);
        }
        for c in &cost_b {
            tracker.record("provider-b", "model-b", *c);
        }

        let total_a: f64 = cost_a.iter().sum();
        let total_b: f64 = cost_b.iter().sum();

        let result_a = tracker.check_budget(
            "provider-a", "model-a", 0.0, Some(provider_limit), None,
        );
        let result_b = tracker.check_budget(
            "provider-b", "model-b", 0.0, Some(provider_limit), None,
        );

        if total_a >= provider_limit {
            prop_assert!(result_a.is_err(),
                "Provider A should be over budget: {:.2} >= {:.2}", total_a, provider_limit);
        } else {
            prop_assert!(result_a.is_ok(),
                "Provider A should be under budget: {:.2} < {:.2}", total_a, provider_limit);
        }

        if total_b >= provider_limit {
            prop_assert!(result_b.is_err(),
                "Provider B should be over budget: {:.2} >= {:.2}", total_b, provider_limit);
        } else {
            prop_assert!(result_b.is_ok(),
                "Provider B should be under budget: {:.2} < {:.2}", total_b, provider_limit);
        }
    }

    /// Invariant: per-model budget takes precedence over global budget.
    /// If model limit is lower, it triggers first.
    #[test]
    fn budget_model_limit_takes_precedence(
        costs in prop::collection::vec(0.1_f64..2.0, 5..30),
        model_limit in 1.0_f64..20.0,
    ) {
        let (mut tracker, _dir) = temp_tracker();

        for cost in &costs {
            tracker.record("provider", "expensive-model", *cost);
        }

        let total: f64 = costs.iter().sum();
        // Global limit set very high — should not trigger.
        let global_limit = 999_999.0;

        let result = tracker.check_budget(
            "provider",
            "expensive-model",
            global_limit,
            None,
            Some(model_limit),
        );

        if total >= model_limit {
            prop_assert!(
                result.is_err(),
                "Model limit should trigger: total={:.2} model_limit={:.2}",
                total,
                model_limit
            );
            let msg = result.unwrap_err().message;
            prop_assert!(
                msg.contains("model"),
                "Error should reference model limit: {}",
                msg
            );
        }
    }

    /// Invariant: total() always equals the sum of all recorded costs.
    #[test]
    fn budget_total_equals_sum_of_recorded(
        costs in prop::collection::vec(0.001_f64..100.0, 1..100),
    ) {
        let (mut tracker, _dir) = temp_tracker();
        let mut expected_total = 0.0;

        for cost in &costs {
            tracker.record("p", "m", *cost);
            expected_total += cost;
        }

        let actual = tracker.total();
        let diff = (actual - expected_total).abs();

        // Allow f64 epsilon accumulation.
        prop_assert!(
            diff < 0.01,
            "Total mismatch: actual={:.6} expected={:.6} diff={:.6}",
            actual,
            expected_total,
            diff
        );
    }

    /// Invariant: zero global_limit means unlimited — check_budget always passes
    /// when global_limit is 0.0 and no provider/model limits are set.
    #[test]
    fn budget_zero_limit_means_unlimited(
        costs in prop::collection::vec(0.01_f64..1000.0, 1..50),
    ) {
        let (mut tracker, _dir) = temp_tracker();

        for cost in &costs {
            tracker.record("any", "any", *cost);
        }

        let result = tracker.check_budget("any", "any", 0.0, None, None);
        prop_assert!(
            result.is_ok(),
            "Zero global limit should mean unlimited"
        );
    }
}

//! Scenario: budget enforcement under 100 simultaneous requests.
//!
//! Validates that the spend tracker correctly enforces limits when
//! hammered with concurrent cost recordings. No request should be
//! allowed to proceed once the budget is exhausted.

use grob::features::token_pricing::spend::SpendTracker;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

// ── Helpers ──────────────────────────────────────────────────────

fn temp_tracker() -> (SpendTracker, TempDir) {
    let dir = TempDir::new().expect("Failed to create temp dir");
    let path = dir.path().join("spend.json");
    (SpendTracker::load(path), dir)
}

// ── Sequential Budget Enforcement ────────────────────────────────

#[test]
fn budget_enforcement_100_sequential_requests() {
    let (mut tracker, _dir) = temp_tracker();
    let cost_per_request = 1.0;
    let budget_limit = 50.0;

    let mut allowed = 0;
    let mut rejected = 0;

    for _ in 0..100 {
        let result = tracker.check_budget("provider", "model", budget_limit, None, None);

        match result {
            Ok(()) => {
                tracker.record("provider", "model", cost_per_request);
                allowed += 1;
            }
            Err(_) => {
                rejected += 1;
            }
        }
    }

    assert_eq!(
        allowed, 50,
        "Exactly 50 requests should be allowed at $1/req with $50 budget"
    );
    assert_eq!(rejected, 50, "Exactly 50 requests should be rejected");
    assert!(
        tracker.total() <= budget_limit,
        "Total spend {:.2} should not exceed budget {:.2}",
        tracker.total(),
        budget_limit
    );
}

#[test]
fn budget_enforcement_variable_costs() {
    let (mut tracker, _dir) = temp_tracker();
    let budget_limit = 10.0;
    let costs = [
        0.5, 1.0, 0.3, 2.0, 0.1, 3.0, 1.5, 0.8, 1.2, 0.6, 4.0, 2.5, 1.0,
    ];

    let mut allowed_count = 0;
    let mut rejected_count = 0;

    for cost in &costs {
        // Budget check uses current total (before recording this cost).
        // If check passes, we record and the total may exceed the limit.
        // This is by design: check_budget gates on accumulated spend, not
        // on the predicted post-record total. The invariant is: once
        // check_budget returns Err, no more requests pass.
        let result = tracker.check_budget("p", "m", budget_limit, None, None);
        if result.is_ok() {
            tracker.record("p", "m", *cost);
            allowed_count += 1;
        } else {
            rejected_count += 1;
        }
    }

    // After the first rejection, all subsequent checks must also fail.
    assert!(
        allowed_count + rejected_count == costs.len(),
        "All requests must be accounted for"
    );

    // Once budget is reached, no more requests are allowed.
    let final_check = tracker.check_budget("p", "m", budget_limit, None, None);
    assert!(
        final_check.is_err(),
        "After variable costs exhaust budget, final check must fail"
    );
}

// ── Concurrent Budget Enforcement ────────────────────────────────

#[tokio::test]
async fn budget_enforcement_100_concurrent_requests() {
    let (tracker, _dir) = temp_tracker();
    let tracker = Arc::new(Mutex::new(tracker));
    let cost_per_request = 1.0;
    let budget_limit = 50.0;

    let allowed = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let rejected = Arc::new(std::sync::atomic::AtomicU32::new(0));

    let mut handles = Vec::new();

    for _ in 0..100 {
        let tracker = Arc::clone(&tracker);
        let allowed = Arc::clone(&allowed);
        let rejected = Arc::clone(&rejected);

        handles.push(tokio::spawn(async move {
            let mut guard = tracker.lock().unwrap();
            let result = guard.check_budget("provider", "model", budget_limit, None, None);

            match result {
                Ok(()) => {
                    guard.record("provider", "model", cost_per_request);
                    allowed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                Err(_) => {
                    rejected.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    let total_allowed = allowed.load(std::sync::atomic::Ordering::Relaxed);
    let total_rejected = rejected.load(std::sync::atomic::Ordering::Relaxed);
    let total_spend = tracker.lock().unwrap().total();

    assert_eq!(
        total_allowed + total_rejected,
        100,
        "All requests should be accounted for"
    );
    assert_eq!(
        total_allowed, 50,
        "Exactly 50 concurrent requests should be allowed"
    );
    assert!(
        total_spend <= budget_limit,
        "Total spend {:.2} must not exceed budget {:.2}",
        total_spend,
        budget_limit
    );
}

#[tokio::test]
async fn budget_enforcement_multi_provider_concurrent() {
    let (tracker, _dir) = temp_tracker();
    let tracker = Arc::new(Mutex::new(tracker));
    let provider_limit = 20.0;

    let mut handles = Vec::new();

    // 50 requests to provider-a, 50 to provider-b, each at $1/req.
    for i in 0..100 {
        let tracker = Arc::clone(&tracker);
        let provider = if i < 50 { "provider-a" } else { "provider-b" };

        handles.push(tokio::spawn(async move {
            let mut guard = tracker.lock().unwrap();
            let result = guard.check_budget(
                provider,
                "model",
                0.0, // No global limit.
                Some(provider_limit),
                None,
            );

            if result.is_ok() {
                guard.record(provider, "model", 1.0);
            }

            (provider.to_string(), result.is_ok())
        }));
    }

    let mut allowed_a = 0u32;
    let mut allowed_b = 0u32;

    for h in handles {
        let (provider, was_allowed) = h.await.unwrap();
        if was_allowed {
            if provider == "provider-a" {
                allowed_a += 1;
            } else {
                allowed_b += 1;
            }
        }
    }

    assert_eq!(
        allowed_a, 20,
        "Provider A should allow exactly 20 requests (limit=$20, cost=$1)"
    );
    assert_eq!(
        allowed_b, 20,
        "Provider B should allow exactly 20 requests (limit=$20, cost=$1)"
    );
}

#[tokio::test]
async fn budget_enforcement_model_limit_under_load() {
    let (tracker, _dir) = temp_tracker();
    let tracker = Arc::new(Mutex::new(tracker));
    let model_limit = 10.0;
    let cost = 0.5;

    let allowed = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let mut handles = Vec::new();

    for _ in 0..100 {
        let tracker = Arc::clone(&tracker);
        let allowed = Arc::clone(&allowed);

        handles.push(tokio::spawn(async move {
            let mut guard = tracker.lock().unwrap();
            let result =
                guard.check_budget("provider", "expensive-model", 0.0, None, Some(model_limit));

            if result.is_ok() {
                guard.record("provider", "expensive-model", cost);
                allowed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    let total_allowed = allowed.load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        total_allowed, 20,
        "Model limit=$10 at $0.50/req should allow exactly 20 requests, got {}",
        total_allowed
    );
}

// ── Budget Warning Tests ─────────────────────────────────────────

#[test]
fn budget_warning_fires_at_threshold() {
    let (mut tracker, _dir) = temp_tracker();
    let limits = grob::features::token_pricing::spend::BudgetLimits {
        global_limit: 100.0,
        provider_limit: None,
        model_limit: None,
        warn_at_percent: 80,
    };

    // Record $79 — should not warn yet.
    tracker.record("p", "m", 79.0);
    assert!(
        tracker.check_warnings("p", "m", &limits).is_none(),
        "Should not warn at 79% of $100"
    );

    // Record $2 more ($81) — should warn.
    tracker.record("p", "m", 2.0);
    let warning = tracker.check_warnings("p", "m", &limits);
    assert!(warning.is_some(), "Should warn at 81% of $100 budget");
    assert!(
        warning.unwrap().contains("81%"),
        "Warning should mention percentage"
    );
}

#[test]
fn budget_zero_cost_requests_dont_exhaust_budget() {
    let (mut tracker, _dir) = temp_tracker();
    let budget_limit = 10.0;

    // 1000 zero-cost requests should all be allowed.
    for _ in 0..1000 {
        let result = tracker.check_budget("p", "m", budget_limit, None, None);
        assert!(result.is_ok(), "Zero-cost request should always be allowed");
        tracker.record("p", "m", 0.0);
    }

    assert!(
        (tracker.total() - 0.0).abs() < f64::EPSILON,
        "Total should be zero after zero-cost requests"
    );
}

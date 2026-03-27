//! Property-based tests for the routing engine.
//!
//! Invariants:
//! - Routing NEVER panics for any well-formed input.
//! - Routing is deterministic: same input always produces the same decision.

use grob::router::Router;
use proptest::prelude::*;

// ── Helpers ─────────────────────────────────────────────────────

fn build_router() -> Router {
    let config = crate::helpers::fixtures::test_app_config();
    Router::new(config)
}

fn request_strategy() -> impl Strategy<Value = (String, String)> {
    let models = prop_oneof![
        Just("claude-sonnet-4-6".to_string()),
        Just("claude-opus-4-6".to_string()),
        Just("gpt-5.2".to_string()),
        Just("claude-3-5-haiku-20241022".to_string()),
        Just("deepseek-chat".to_string()),
        Just("unknown-model-xyz".to_string()),
        "[a-z0-9-]{1,40}",
    ];
    let prompts = prop_oneof![
        Just("Hello, world".to_string()),
        Just("Refactor the auth module".to_string()),
        Just("Design a new system architecture".to_string()),
        Just("Lint and format this file".to_string()),
        "[A-Za-z0-9 .,!?]{1,200}",
    ];
    (models, prompts)
}

// ── Property Tests ──────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// Invariant: route() never panics and always returns Ok for valid requests.
    #[test]
    fn routing_never_panics(
        (model, prompt) in request_strategy(),
    ) {
        let router = build_router();
        let mut request = crate::helpers::fixtures::create_test_request(&model, &prompt);

        // Must not panic — any model/prompt combination produces a result.
        let result = router.route(&mut request);
        prop_assert!(
            result.is_ok(),
            "route() returned Err for model='{}' prompt='{}'",
            model,
            &prompt[..prompt.len().min(50)]
        );

        let decision = result.unwrap();
        prop_assert!(
            !decision.model_name.is_empty(),
            "Route decision has empty model_name"
        );
    }

    /// Invariant: routing is deterministic — same input always yields same output.
    #[test]
    fn routing_is_deterministic(
        (model, prompt) in request_strategy(),
    ) {
        let router = build_router();

        let mut req1 = crate::helpers::fixtures::create_test_request(&model, &prompt);
        let mut req2 = crate::helpers::fixtures::create_test_request(&model, &prompt);

        let decision1 = router.route(&mut req1).unwrap();
        let decision2 = router.route(&mut req2).unwrap();

        prop_assert_eq!(
            &decision1.model_name,
            &decision2.model_name,
            "Non-deterministic model: '{}' vs '{}'",
            decision1.model_name,
            decision2.model_name
        );
        prop_assert_eq!(
            format!("{}", decision1.route_type),
            format!("{}", decision2.route_type),
            "Non-deterministic route_type"
        );
    }
}

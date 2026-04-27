//! Snapshot tests for routing decisions across all builtin presets.
//!
//! Each preset is loaded, parsed into a [`RouterConfig`], and routed against
//! a matrix of request shapes. The resulting [`RouteDecision`] is captured
//! via `insta::assert_debug_snapshot!` to detect unintended routing regressions.

use grob::cli::RouterConfig;
use grob::models::{CanonicalRequest, RouteDecision};
use grob::preset::preset_content;
use grob::routing::classify::Router;

// ── Helpers ──────────────────────────────────────────────────────

/// Parses a preset TOML into an AppConfig with the preset's router config
/// and test defaults for everything else.
fn load_preset_config(name: &str) -> grob::cli::AppConfig {
    let toml_str = preset_content(name).unwrap_or_else(|e| {
        panic!("Failed to load preset '{}': {}", name, e);
    });
    let value: toml::Value = toml::from_str(&toml_str).unwrap_or_else(|e| {
        panic!("Failed to parse preset '{}' TOML: {}", name, e);
    });

    let router: RouterConfig = value
        .get("router")
        .expect("Preset must have [router] section")
        .clone()
        .try_into()
        .expect("Invalid router config in preset");

    // Build AppConfig from the fixture helper and override the router.
    let mut config = crate::helpers::fixtures::test_app_config();
    config.router = router;

    // Parse models from preset if present.
    if let Some(models_val) = value.get("models") {
        if let Ok(m) = models_val.clone().try_into() {
            config.models = m;
        }
    }

    // Parse providers from preset if present.
    if let Some(providers_val) = value.get("providers") {
        if let Ok(p) = providers_val.clone().try_into() {
            config.providers = p;
        }
    }

    config
}

fn make_request(model: &str, text: &str) -> CanonicalRequest {
    crate::helpers::fixtures::create_test_request(model, text)
}

fn make_thinking_request(model: &str, text: &str) -> CanonicalRequest {
    crate::helpers::fixtures::create_thinking_request(model, text)
}

fn make_websearch_request(model: &str, text: &str) -> CanonicalRequest {
    crate::helpers::fixtures::create_websearch_request(model, text)
}

fn make_background_request(text: &str) -> CanonicalRequest {
    make_request("claude-3-5-haiku-20241022", text)
}

/// Snapshot a routing decision with a human-readable format.
fn snapshot_route(decision: &RouteDecision) -> String {
    format!(
        "model={} type={} matched={}",
        decision.model_name,
        decision.route_type,
        decision.matched_prompt.as_deref().unwrap_or("none")
    )
}

/// Routes all standard request shapes through a preset and returns a
/// vector of labeled snapshot strings.
fn route_matrix(router: &Router) -> Vec<(String, String)> {
    let cases: Vec<(&str, CanonicalRequest)> = vec![
        (
            "default_simple",
            make_request("claude-sonnet-4-6", "Hello, world"),
        ),
        (
            "default_non_claude",
            make_request("gpt-5.2", "Hello, world"),
        ),
        (
            "thinking_enabled",
            make_thinking_request("claude-sonnet-4-6", "Architect a microservice"),
        ),
        (
            "websearch_tool",
            make_websearch_request("claude-sonnet-4-6", "Search for Rust news"),
        ),
        (
            "background_haiku",
            make_background_request("Format this code"),
        ),
        (
            "prompt_rule_refactor",
            make_request(
                "claude-sonnet-4-6",
                "Please refactor the authentication module",
            ),
        ),
        (
            "prompt_rule_lint",
            make_request("claude-sonnet-4-6", "Lint and format the file"),
        ),
        (
            "prompt_rule_architect",
            make_request(
                "claude-sonnet-4-6",
                "Design a new system architecture for payments",
            ),
        ),
    ];

    cases
        .into_iter()
        .filter_map(|(label, mut req)| {
            router
                .route(&mut req)
                .ok()
                .map(|decision| (label.to_string(), snapshot_route(&decision)))
        })
        .collect()
}

// ── Preset Snapshot Tests ────────────────────────────────────────

macro_rules! preset_snapshot_test {
    ($name:ident, $preset:literal) => {
        #[test]
        fn $name() {
            let config = load_preset_config($preset);
            let router = Router::new(config);
            let results = route_matrix(&router);
            let snapshot: Vec<String> = results
                .iter()
                .map(|(label, route)| format!("{}: {}", label, route))
                .collect();
            insta::assert_debug_snapshot!(snapshot);
        }
    };
}

preset_snapshot_test!(snapshot_preset_perf, "perf");
preset_snapshot_test!(snapshot_preset_ultra_cheap, "ultra-cheap");
preset_snapshot_test!(snapshot_preset_eu_eco, "eu-eco");
preset_snapshot_test!(snapshot_preset_eu_pro, "eu-pro");
preset_snapshot_test!(snapshot_preset_eu_max, "eu-max");
preset_snapshot_test!(snapshot_preset_gdpr, "gdpr");
preset_snapshot_test!(snapshot_preset_eu_ai_act, "eu-ai-act");

// ── Cross-Preset Consistency Tests ──────────────────────────────

#[test]
fn snapshot_all_presets_have_default_route() {
    let presets = [
        "perf",
        "ultra-cheap",
        "eu-eco",
        "eu-pro",
        "eu-max",
        "gdpr",
        "eu-ai-act",
    ];
    let mut results: Vec<String> = Vec::new();

    for preset_name in &presets {
        let config = load_preset_config(preset_name);
        let router = Router::new(config);
        let mut req = make_request("claude-sonnet-4-6", "Hello");
        if let Ok(decision) = router.route(&mut req) {
            results.push(format!(
                "{}: model={} type={}",
                preset_name, decision.model_name, decision.route_type
            ));
        } else {
            results.push(format!("{}: ROUTE_FAILED", preset_name));
        }
    }

    insta::assert_debug_snapshot!(results);
}

#[test]
fn snapshot_thinking_routes_differ_from_default() {
    let presets = ["perf", "ultra-cheap", "eu-eco", "eu-pro", "eu-max"];
    let mut results: Vec<String> = Vec::new();

    for preset_name in &presets {
        let config = load_preset_config(preset_name);
        let router = Router::new(config);

        let mut default_req = make_request("claude-sonnet-4-6", "Hello");
        let mut think_req =
            make_thinking_request("claude-sonnet-4-6", "Architect a distributed system");

        let default_decision = router.route(&mut default_req).unwrap();
        let think_decision = router.route(&mut think_req).unwrap();

        results.push(format!(
            "{}: default={} think={} differs={}",
            preset_name,
            default_decision.model_name,
            think_decision.model_name,
            default_decision.model_name != think_decision.model_name
        ));
    }

    insta::assert_debug_snapshot!(results);
}

#[test]
fn snapshot_gdpr_presets_enforce_region() {
    let gdpr_presets = ["gdpr", "eu-ai-act"];
    let mut results: Vec<String> = Vec::new();

    for preset_name in &gdpr_presets {
        let config = load_preset_config(preset_name);
        results.push(format!(
            "{}: gdpr={} region={:?}",
            preset_name, config.router.gdpr, config.router.region
        ));
    }

    insta::assert_debug_snapshot!(results);
}

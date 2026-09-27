use super::preflight::{
    dlp_input_scan_disabled, dlp_reports_triggered, redaction_audit_rules, reports_have_pii,
    should_escalate_compliance, warn_stripped_tools,
};
use super::*;
use tracing_test::traced_test;

// ── scan_dlp_input guards ──

#[test]
fn dlp_input_scan_disabled_inverts_scan_flag() {
    // `!scan_input`: disabled when scanning is off. The "delete !" mutant
    // would return the flag verbatim, flipping both outcomes.
    assert!(dlp_input_scan_disabled(false));
    assert!(!dlp_input_scan_disabled(true));
}

#[test]
fn should_escalate_compliance_requires_both_flags() {
    // `enabled && risk_classification`: the `&&` → `||` mutant would
    // escalate whenever either flag is set, so assert all four cells.
    assert!(should_escalate_compliance(true, true));
    assert!(!should_escalate_compliance(true, false));
    assert!(!should_escalate_compliance(false, true));
    assert!(!should_escalate_compliance(false, false));
}

#[test]
fn dlp_reports_triggered_flags_nonempty_reports() {
    // `!reports.is_empty()`: triggered only when DLP produced a report.
    // The "delete !" mutant would invert both outcomes.
    assert!(!dlp_reports_triggered::<()>(&[]));
    assert!(dlp_reports_triggered(&[()]));
}

fn report(
    rule_type: crate::features::dlp::DlpRuleType,
    detail: &str,
) -> crate::features::dlp::DlpActionReport {
    crate::features::dlp::DlpActionReport {
        action: crate::features::dlp::DlpAction::Redact,
        rule_type,
        detail: detail.to_string(),
    }
}

#[test]
fn redaction_audit_rules_names_each_report() {
    use crate::features::dlp::DlpRuleType;
    // Each report becomes "<rule_type>: <detail>" so the audit log names a
    // caviardage like it names a block. Empty in, empty out.
    assert!(redaction_audit_rules(&[]).is_empty());
    let rules = redaction_audit_rules(&[
        report(DlpRuleType::Secret, "AWS access key"),
        report(DlpRuleType::Pii, "credit card"),
    ]);
    assert_eq!(rules, vec!["secret: AWS access key", "pii: credit card"]);
}

#[test]
fn reports_have_pii_detects_only_pii_rule_type() {
    use crate::features::dlp::DlpRuleType;
    // PII drives the C2-vs-C1 split. A secret-only set is C1 (false); any
    // PII report flips it to C2 (true). The `any` → `all` mutant would miss
    // a mixed set, so assert all three shapes.
    assert!(!reports_have_pii(&[]));
    assert!(!reports_have_pii(&[report(DlpRuleType::Secret, "token")]));
    assert!(reports_have_pii(&[
        report(DlpRuleType::Secret, "token"),
        report(DlpRuleType::Pii, "iban"),
    ]));
}

#[traced_test]
#[test]
fn warn_stripped_tools_logs_only_when_nonempty() {
    // The "delete !" mutant would warn on an empty strip list and stay
    // silent on a real one — assert both directions against the log.
    warn_stripped_tools(&[]);
    assert!(!logs_contain("stripped malformed inbound tools"));
    warn_stripped_tools(&["bogus_tool".to_string()]);
    assert!(logs_contain("stripped malformed inbound tools"));
}

// ── dispatch routing guards ──

#[test]
fn fan_out_selection_preserves_tier_priority_and_model_fallback() {
    use crate::cli::{FanOutConfig, FanOutMode, TierConfig};
    use crate::models::{RouteDecision, RouteType};
    use crate::routing::classify::ComplexityTier;
    for (hint, tier_fanout, strategy, expected) in [
        (
            Some(ComplexityTier::Complex),
            true,
            ModelStrategy::FanOut,
            Some(FanOutMode::Fastest),
        ),
        (
            Some(ComplexityTier::Complex),
            false,
            ModelStrategy::FanOut,
            Some(FanOutMode::Weighted),
        ),
        (
            Some(ComplexityTier::Medium),
            true,
            ModelStrategy::FanOut,
            Some(FanOutMode::Weighted),
        ),
        (
            None,
            true,
            ModelStrategy::FanOut,
            Some(FanOutMode::Weighted),
        ),
        (
            Some(ComplexityTier::Complex),
            true,
            ModelStrategy::Fallback,
            Some(FanOutMode::Fastest),
        ),
        (None, true, ModelStrategy::Fallback, None),
    ] {
        let mut config = policy_config("default", "");
        config.models[0].strategy = strategy;
        config.models[0].fan_out = Some(FanOutConfig {
            mode: FanOutMode::Weighted,
            judge_model: None,
            judge_criteria: None,
            count: Some(2),
        });
        config.tiers = vec![TierConfig {
            name: "complex".into(),
            model: None,
            providers: vec!["anthropic".into()],
            fanout: tier_fanout,
            match_conditions: None,
        }];
        let inner = ReloadableState::new(
            config.clone(),
            crate::routing::classify::Router::new(config),
            Arc::new(crate::providers::ProviderRegistry::new()),
        );
        let decision = RouteDecision {
            model_name: "alpha".into(),
            route_type: RouteType::Default,
            matched_prompt: None,
            complexity_tier: hint,
        };
        let selected = resolve_fan_out_config(&inner, &decision);
        assert_eq!(selected.as_ref().map(|c| c.mode.clone()), expected);
        if expected == Some(FanOutMode::Weighted) {
            assert_eq!(selected.unwrap().count, Some(2));
        }
    }
}

#[test]
fn context_phase_distinguishes_safe_warning_and_blocked_requests() {
    let request: CanonicalRequest = serde_json::from_value(serde_json::json!({
        "model":"alpha", "max_tokens":20,
        "messages":[{"role":"user", "content":"x".repeat(4000)}]
    }))
    .unwrap();
    let tokens = super::super::estimate_input_tokens(&request);
    for (window, expected) in [
        (tokens * 2, "safe"),
        (tokens * 100 / 85, "warn"),
        (tokens, "block"),
    ] {
        let mut config = policy_config("default", "");
        config.models[0].context_window_tokens = Some(window);
        let inner = ReloadableState::new(
            config.clone(),
            crate::routing::classify::Router::new(config),
            Arc::new(crate::providers::ProviderRegistry::new()),
        );
        match (
            expected,
            enforce_context_guard(&inner, &request, "alpha", None),
        ) {
            ("safe", Ok(None)) => {}
            ("warn", Ok(Some(info))) => {
                assert_eq!(info.context_window, window);
                assert!(!info.should_compact);
            }
            ("block", Err(RequestError::ContextWindowExceeded { context_window, .. })) => {
                assert_eq!(context_window, window);
            }
            _ => panic!("incorrect context guard outcome for {expected}"),
        }
    }
}

#[cfg(feature = "mcp")]
#[test]
fn parse_complexity_hint_rejects_unknown_values() {
    assert_eq!(
        parse_complexity_hint(serde_json::json!("trivial")).expect("valid hint"),
        ComplexityHint::Trivial
    );
    assert!(parse_complexity_hint(serde_json::json!("urgent")).is_err());
}

// ── allowed_models post-routing enforcement (real dispatch() wiring) ──

/// Provider that records whether it was reached. The Forbidden path must
/// reject before any provider call, so `called` must stay `false`.
struct CountingProvider {
    called: Arc<std::sync::atomic::AtomicBool>,
}

#[async_trait::async_trait]
impl crate::providers::LlmProvider for CountingProvider {
    async fn send_message(
        &self,
        _request: CanonicalRequest,
    ) -> Result<ProviderResponse, crate::providers::error::ProviderError> {
        self.called.store(true, std::sync::atomic::Ordering::SeqCst);
        Err(crate::providers::error::ProviderError::ApiError {
            status: 400,
            message: "mock provider must not be reached".to_string(),
        })
    }

    async fn send_message_stream(
        &self,
        _request: CanonicalRequest,
    ) -> Result<crate::providers::StreamResponse, crate::providers::error::ProviderError> {
        self.called.store(true, std::sync::atomic::Ordering::SeqCst);
        Err(crate::providers::error::ProviderError::ApiError {
            status: 400,
            message: "mock provider must not be reached".to_string(),
        })
    }

    async fn count_tokens(
        &self,
        _request: crate::models::CountTokensRequest,
    ) -> Result<crate::models::CountTokensResponse, crate::providers::error::ProviderError> {
        Err(crate::providers::error::ProviderError::ApiError {
            status: 400,
            message: "mock".to_string(),
        })
    }

    fn supports_model(&self, _model: &str) -> bool {
        true
    }
}

/// Builds a minimal real [`AppState`] with a mock provider registered as
/// "mock", delegating to the shared [`crate::server::test_app_state`] builder.
fn test_app_state(
    config: crate::cli::AppConfig,
    called: Arc<std::sync::atomic::AtomicBool>,
) -> Arc<AppState> {
    let mut registry = crate::providers::ProviderRegistry::new();
    registry.insert_provider_for_test("mock", Arc::new(CountingProvider { called }));
    crate::server::test_app_state(config, registry)
}

/// dispatch() must reject a scoped key when routing remaps the inbound model
/// to a forbidden one — BEFORE any provider is reached. Red if dispatch stops
/// passing `ctx.allowed_models` to `resolve_provider_mappings`.
#[tokio::test]
async fn dispatch_rejects_remapped_forbidden_model_before_provider() {
    use crate::models::{Message, MessageContent, ThinkingConfig};

    // `thinking` routes via `[router] think = "beta"` → decision.model_name
    // becomes "beta", which the key (allowed only "alpha") forbids.
    let toml = r#"
[server]
host = "127.0.0.1"
port = 18097

[router]
default = "alpha"
think = "beta"

[[providers]]
name = "mock"
provider_type = "openai"
auth_type = "apikey"
api_key = "sk-test"
base_url = "http://127.0.0.1:1"
models = ["alpha", "beta"]

[[models]]
name = "alpha"
[[models.mappings]]
priority = 1
provider = "mock"
actual_model = "alpha"

[[models]]
name = "beta"
[[models.mappings]]
priority = 1
provider = "mock"
actual_model = "beta"
"#;
    let config = crate::cli::AppConfig::from_content(toml, "dispatch_allowed_models_test")
        .expect("config parses");

    let called = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let state = test_app_state(config, called.clone());
    let inner = state.snapshot();
    let dlp: Option<Arc<DlpEngine>> = None;
    let headers = HeaderMap::new();

    let ctx = DispatchContext {
        state: &state,
        inner: &inner,
        dlp: &dlp,
        model: "alpha".to_string(),
        is_streaming: false,
        tenant_id: None,
        #[cfg(feature = "agents")]
        agent: crate::features::agents::AgentContext::default(),
        allowed_models: Some(vec!["alpha".to_string()]),
        allowed_providers: Vec::new(),
        peer_ip: "127.0.0.1".to_string(),
        req_id: "test-req",
        start_time: std::time::Instant::now(),
        headers: &headers,
        trace_id: None,
        audited: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        #[cfg(feature = "policies")]
        resolved_policy: None,
    };

    let mut request = CanonicalRequest {
        model: "alpha".to_string(),
        messages: vec![Message {
            role: "user".to_string(),
            content: MessageContent::Text("Think hard.".to_string()),
        }],
        max_tokens: 1024,
        system: None,
        tools: None,
        tool_choice: None,
        thinking: Some(ThinkingConfig {
            r#type: "enabled".to_string(),
            budget_tokens: Some(10_000),
        }),
        temperature: None,
        top_p: None,
        top_k: None,
        stop_sequences: None,
        stream: None,
        metadata: None,
        extensions: Default::default(),
    };

    let result = dispatch(&ctx, &mut request).await;

    assert!(
        matches!(result, Err(RequestError::Forbidden(_))),
        "scoped key must be rejected (403) on the remapped 'beta' model"
    );
    assert!(
        !called.load(std::sync::atomic::Ordering::SeqCst),
        "the provider must NOT be reached when the resolved model is forbidden"
    );
}

#[tokio::test]
async fn dispatch_preserves_context_warning_on_direct_provider_lookup() {
    use crate::models::{Message, MessageContent};

    let toml = r#"
[server]
host = "127.0.0.1"
port = 18098

[router]
default = "alpha"

[[providers]]
name = "mock"
provider_type = "openai"
auth_type = "apikey"
api_key = "sk-test"
base_url = "http://127.0.0.1:1"
models = ["alpha"]

[[models]]
name = "alpha"
mappings = []
context_window_tokens = 100
"#;
    let config = crate::cli::AppConfig::from_content(toml, "dispatch_direct_lookup_guard_test")
        .expect("config parses");
    let mut registry = crate::providers::ProviderRegistry::new();
    registry.insert_provider_for_test(
        "mock",
        Arc::new(crate::providers::mocks::MockLlmProvider::text(
            "alpha", "ok",
        )),
    );
    let state = crate::server::test_app_state(config, registry);
    let inner = state.snapshot();
    let dlp: Option<Arc<DlpEngine>> = None;
    let headers = HeaderMap::new();
    let ctx = DispatchContext {
        state: &state,
        inner: &inner,
        dlp: &dlp,
        model: "alpha".to_string(),
        is_streaming: false,
        tenant_id: None,
        #[cfg(feature = "agents")]
        agent: crate::features::agents::AgentContext::default(),
        allowed_models: None,
        allowed_providers: Vec::new(),
        peer_ip: "127.0.0.1".to_string(),
        req_id: "test-req",
        start_time: std::time::Instant::now(),
        headers: &headers,
        trace_id: None,
        audited: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        #[cfg(feature = "policies")]
        resolved_policy: None,
    };

    let mut request = CanonicalRequest {
        model: "alpha".to_string(),
        messages: vec![Message {
            role: "user".to_string(),
            content: MessageContent::Text("x".repeat(320)),
        }],
        max_tokens: 16,
        system: None,
        tools: None,
        tool_choice: None,
        thinking: None,
        temperature: None,
        top_p: None,
        top_k: None,
        stop_sequences: None,
        stream: None,
        metadata: None,
        extensions: Default::default(),
    };

    let result = dispatch(&ctx, &mut request)
        .await
        .expect("dispatch succeeds");
    let DispatchResult::Complete { context_guard, .. } = result else {
        panic!("expected non-streaming response");
    };
    let info = context_guard.expect("context warning must survive direct lookup");
    assert_eq!(info.context_window, 100);
    assert!(info.usage_ratio >= 0.80);
    assert!(!info.should_compact);
}

// ── SLICE 3: policy overrides (matching fix + budget + rate_limit) ──

/// Config declaring one policy with a `route_type` condition plus the given
/// `[policies.*]` override TOML block.
fn policy_config(route_type: &str, override_toml: &str) -> crate::cli::AppConfig {
    let toml = format!(
        r#"
[server]
host = "127.0.0.1"
port = 18093

[router]
default = "alpha"

[[providers]]
name = "anthropic"
provider_type = "openai"
auth_type = "apikey"
api_key = "sk-test"
base_url = "http://127.0.0.1:1"
models = ["alpha"]

[[models]]
name = "alpha"
[[models.mappings]]
priority = 1
provider = "anthropic"
actual_model = "alpha"

[[policies]]
name = "p"
[policies.match]
route_type = "{route_type}"
{override_toml}
"#
    );
    crate::cli::AppConfig::from_content(&toml, "policy_override_test").expect("config parses")
}

/// Config with a `provider`-keyed policy and TWO mappings (anthropic at
/// priority 1, openrouter at priority 2), so a fallback to a non-first
/// provider can be exercised.
#[cfg(feature = "policies")]
fn provider_keyed_config(provider: &str, override_toml: &str) -> crate::cli::AppConfig {
    let toml = format!(
        r#"
[server]
host = "127.0.0.1"
port = 18092

[router]
default = "alpha"

[[providers]]
name = "anthropic"
provider_type = "openai"
auth_type = "apikey"
api_key = "sk-test"
base_url = "http://127.0.0.1:1"
models = ["alpha"]

[[providers]]
name = "openrouter"
provider_type = "openai"
auth_type = "apikey"
api_key = "sk-test"
base_url = "http://127.0.0.1:1"
models = ["alpha"]

[[models]]
name = "alpha"
[[models.mappings]]
priority = 1
provider = "anthropic"
actual_model = "alpha"
[[models.mappings]]
priority = 2
provider = "openrouter"
actual_model = "alpha"

[[policies]]
name = "p"
[policies.match]
provider = "{provider}"
{override_toml}
"#
    );
    crate::cli::AppConfig::from_content(&toml, "provider_keyed_policy_test").expect("config parses")
}

/// Drives a real `dispatch()` for model "alpha" (a plain request routes to
/// `default`), so the policy enforcement wiring is actually exercised.
#[cfg(feature = "policies")]
async fn run_dispatch(
    state: &Arc<AppState>,
    tenant: Option<&str>,
) -> Result<DispatchResult, RequestError> {
    let inner = state.snapshot();
    let dlp: Option<Arc<DlpEngine>> = None;
    let headers = HeaderMap::new();
    let ctx = DispatchContext {
        state,
        inner: &inner,
        dlp: &dlp,
        model: "alpha".to_string(),
        is_streaming: false,
        tenant_id: tenant.map(|s| s.to_string()),
        #[cfg(feature = "agents")]
        agent: crate::features::agents::AgentContext::default(),
        allowed_models: None,
        allowed_providers: Vec::new(),
        peer_ip: "127.0.0.1".to_string(),
        req_id: "test",
        start_time: std::time::Instant::now(),
        headers: &headers,
        trace_id: None,
        audited: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        resolved_policy: None,
    };
    let mut request: CanonicalRequest = serde_json::from_value(serde_json::json!({
        "model": "alpha",
        "max_tokens": 16,
        "messages": [{ "role": "user", "content": "hi" }]
    }))
    .expect("request");
    dispatch(&ctx, &mut request).await
}

/// Runs dispatch with a request carrying an image, so the media gate is
/// actually exercised.
async fn run_dispatch_with_image(state: &Arc<AppState>) -> Result<DispatchResult, RequestError> {
    let inner = state.snapshot();
    let dlp: Option<Arc<DlpEngine>> = None;
    let headers = HeaderMap::new();
    let ctx = DispatchContext {
        state,
        inner: &inner,
        dlp: &dlp,
        model: "alpha".to_string(),
        is_streaming: false,
        tenant_id: None,
        #[cfg(feature = "agents")]
        agent: crate::features::agents::AgentContext::default(),
        allowed_models: None,
        allowed_providers: Vec::new(),
        peer_ip: "127.0.0.1".to_string(),
        req_id: "test",
        start_time: std::time::Instant::now(),
        headers: &headers,
        trace_id: None,
        audited: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        #[cfg(feature = "policies")]
        resolved_policy: None,
    };
    // A payload that is not a decodable image: blocking inspection cannot
    // complete, so `on_failure = deny` must refuse it.
    let mut request: CanonicalRequest = serde_json::from_value(serde_json::json!({
        "model": "alpha",
        "max_tokens": 16,
        "messages": [{ "role": "user", "content": [
            { "type": "text", "text": "what is this?" },
            { "type": "image", "source": {
                "type": "base64", "media_type": "image/png", "data": "bm90LWFuLWltYWdl"
            } }
        ] }]
    }))
    .expect("request");
    dispatch(&ctx, &mut request).await
}

/// Agent attribution must survive the trip through `DispatchContext`.
///
/// `agent_id()` is what tags a spend journal entry and a retry record with
/// the calling agent. A mutant returning `None` silently drops that
/// attribution — spend still records, so nothing fails, but per-agent
/// accounting quietly becomes anonymous. A mutant returning a constant is
/// worse: it attributes every request to one agent.
#[cfg(feature = "agents")]
#[tokio::test]
async fn agent_id_round_trips_through_the_dispatch_context() {
    use crate::features::agents::{AgentContext, AgentId};

    let state = crate::server::test_app_state(
        policy_config("default", ""),
        crate::providers::ProviderRegistry::new(),
    );
    let inner = state.snapshot();
    let dlp: Option<Arc<DlpEngine>> = None;
    let headers = HeaderMap::new();

    let agent = AgentContext {
        agent_id: Some(AgentId::parse("billing-agent").expect("valid id")),
        ..Default::default()
    };
    let ctx = DispatchContext {
        state: &state,
        inner: &inner,
        dlp: &dlp,
        model: "alpha".to_string(),
        is_streaming: false,
        tenant_id: None,
        agent,
        allowed_models: None,
        allowed_providers: Vec::new(),
        peer_ip: "127.0.0.1".to_string(),
        req_id: "test",
        start_time: std::time::Instant::now(),
        headers: &headers,
        trace_id: None,
        audited: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        #[cfg(feature = "policies")]
        resolved_policy: None,
    };

    assert_eq!(
        ctx.agent_id(),
        Some("billing-agent"),
        "the calling agent must reach spend attribution unchanged"
    );
}

/// No agent must stay no agent.
///
/// Pins the other direction, so a mutant returning a constant id — which
/// would attribute every anonymous request to one agent — is caught.
#[cfg(feature = "agents")]
#[tokio::test]
async fn absent_agent_is_not_invented() {
    let state = crate::server::test_app_state(
        policy_config("default", ""),
        crate::providers::ProviderRegistry::new(),
    );
    let inner = state.snapshot();
    let dlp: Option<Arc<DlpEngine>> = None;
    let headers = HeaderMap::new();
    let ctx = DispatchContext {
        state: &state,
        inner: &inner,
        dlp: &dlp,
        model: "alpha".to_string(),
        is_streaming: false,
        tenant_id: None,
        agent: crate::features::agents::AgentContext::default(),
        allowed_models: None,
        allowed_providers: Vec::new(),
        peer_ip: "127.0.0.1".to_string(),
        req_id: "test",
        start_time: std::time::Instant::now(),
        headers: &headers,
        trace_id: None,
        audited: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        #[cfg(feature = "policies")]
        resolved_policy: None,
    };

    assert_eq!(
        ctx.agent_id(),
        None,
        "an unattributed request must not be credited to an agent"
    );
}

/// The media gate must refuse an uninspectable image before any provider.
///
/// `gate_media` is a security control: `on_failure = "deny"` is the promise
/// that an image which cannot be inspected does not reach the model. A
/// mutant replacing the whole function with `Ok(())` silently disables
/// media blocking, and until this test nothing caught it — the existing
/// dispatch tests all send text-only requests, so the gate was never
/// reached.
///
/// Gated on the `media` feature: without it there is no `[media]` section
/// to configure, and `gate_media` compiles to a no-op.
#[cfg(feature = "media")]
#[tokio::test]
async fn media_gate_blocks_an_uninspectable_image() {
    let toml = r#"
[server]
host = "127.0.0.1"
port = 18092

[router]
default = "alpha"

[media]
mode = "blocking"
on_failure = "deny"

[[providers]]
name = "anthropic"
provider_type = "openai"
auth_type = "apikey"
api_key = "sk-test"
base_url = "http://127.0.0.1:1"
models = ["alpha"]

[[models]]
name = "alpha"
[[models.mappings]]
priority = 1
provider = "anthropic"
actual_model = "alpha"
"#;
    let config =
        crate::cli::AppConfig::from_content(toml, "media_gate_test").expect("config parses");
    let called = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut registry = crate::providers::ProviderRegistry::new();
    registry.insert_provider_for_test(
        "anthropic",
        Arc::new(CountingProvider {
            called: called.clone(),
        }),
    );
    let state = crate::server::test_app_state(config, registry);

    let result = run_dispatch_with_image(&state).await;
    assert!(
        matches!(result, Err(RequestError::Forbidden(_))),
        "an image that cannot be inspected must be refused under \
         on_failure = deny"
    );
    assert!(
        !called.load(std::sync::atomic::Ordering::SeqCst),
        "the provider must NOT be reached when the media gate denies"
    );
}

/// With media inspection off, the same request must pass the gate.
///
/// Pins the other direction: the gate must not reject when it is disabled,
/// so a mutant that always denies is caught too.
#[tokio::test]
async fn media_gate_is_inert_when_disabled() {
    let config = policy_config("default", "");
    let called = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut registry = crate::providers::ProviderRegistry::new();
    registry.insert_provider_for_test(
        "anthropic",
        Arc::new(CountingProvider {
            called: called.clone(),
        }),
    );
    let state = crate::server::test_app_state(config, registry);

    let result = run_dispatch_with_image(&state).await;
    assert!(
        !matches!(result, Err(RequestError::Forbidden(_))),
        "media blocking is off by default; the gate must not refuse"
    );
}

// (1) Matching is fixed: a policy keyed on route_type matches only once the
// context is enriched. The empty pre-route context (route_type = "") — what
// the handler eval produces — never matches, which is the bug.
#[cfg(feature = "policies")]
#[tokio::test]
async fn policy_keyed_on_route_type_matches_only_when_context_is_enriched() {
    use crate::features::policies::context::RequestContext;

    let config = policy_config("background", "[policies.budget]\nmonthly_usd = 1.0");
    let state = crate::server::test_app_state(config, crate::providers::ProviderRegistry::new());
    let inner = state.snapshot();
    let matcher = inner.policy_matcher.as_ref().expect("matcher built");

    let empty = RequestContext {
        route_type: String::new(),
        ..Default::default()
    };
    assert!(
        !matcher.evaluate(&empty).matched,
        "empty pre-route context must NOT match a route_type policy (the bug)"
    );

    let enriched = RequestContext {
        route_type: "background".to_string(),
        ..Default::default()
    };
    let resolved = matcher.evaluate(&enriched);
    assert!(resolved.matched, "enriched context must match the policy");
    assert!(resolved.budget.is_some(), "the budget override is resolved");
}

// (2) Budget override blocks via the REAL dispatch() path, before the
// provider is reached. Red if the per-candidate enforcement is removed from
// the provider loop.
#[cfg(feature = "policies")]
#[tokio::test]
async fn dispatch_policy_budget_override_blocks_before_provider() {
    let config = policy_config("default", "[policies.budget]\nmonthly_usd = 5.0");
    let called = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut registry = crate::providers::ProviderRegistry::new();
    registry.insert_provider_for_test(
        "anthropic",
        Arc::new(CountingProvider {
            called: called.clone(),
        }),
    );
    let state = crate::server::test_app_state(config, registry);

    {
        let mut tracker = state.observability.spend_tracker.lock().await;
        tracker.record("anthropic", "alpha", 10.0); // over the 5.0 cap
    }

    let result = run_dispatch(&state, None).await;
    assert!(
        matches!(result, Err(RequestError::BudgetExceeded { .. })),
        "dispatch must block on the policy budget cap"
    );
    assert!(
        !called.load(std::sync::atomic::Ordering::SeqCst),
        "the provider must NOT be reached when the budget policy blocks"
    );
}

/// A policy budget must take the fleet share like every other cap.
///
/// Otherwise moving a cap into a policy would quietly exempt it from the
/// fleet ceiling: the limit would still be honoured per process, and still
/// be multiplied by the replica count. Spend here sits *under* the
/// configured cap but *over* this replica's share, so it can only block if
/// the share is applied.
#[cfg(feature = "policies")]
#[tokio::test]
async fn dispatch_policy_budget_override_takes_the_fleet_share() {
    let mut config = policy_config("default", "[policies.budget]\nmonthly_usd = 100.0");
    // Four replicas, 5% withheld → this one may spend 100 * 0.95 / 4 = 23.75.
    config.budget.replicas = 4;
    config.budget.margin_percent = 5;

    let called = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut registry = crate::providers::ProviderRegistry::new();
    registry.insert_provider_for_test(
        "anthropic",
        Arc::new(CountingProvider {
            called: called.clone(),
        }),
    );
    let state = crate::server::test_app_state(config, registry);

    {
        let mut tracker = state.observability.spend_tracker.lock().await;
        // Well under the 100.0 policy cap, but over this replica's 23.75.
        tracker.record("anthropic", "alpha", 30.0);
    }

    let result = run_dispatch(&state, None).await;
    assert!(
        matches!(result, Err(RequestError::BudgetExceeded { .. })),
        "a policy budget must be divided across replicas: $30 is under the \
         $100 cap but over this replica's $23.75 share"
    );
    assert!(
        !called.load(std::sync::atomic::Ordering::SeqCst),
        "the provider must not be reached once the share is exhausted"
    );
}

// (3) Rate-limit override throttles via REAL dispatch(): rps = 1, the second
// immediate dispatch is rejected. Red if the per-candidate enforcement is
// removed.
#[cfg(feature = "policies")]
#[tokio::test]
async fn dispatch_policy_rate_limit_override_throttles() {
    let config = policy_config("default", "[policies.rate_limit]\nrps = 1");
    let called = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut registry = crate::providers::ProviderRegistry::new();
    registry.insert_provider_for_test("anthropic", Arc::new(CountingProvider { called }));
    let state = crate::server::test_app_state(config, registry);

    // First dispatch consumes the single token (provider reached, then errors).
    let first = run_dispatch(&state, Some("tenant-1")).await;
    assert!(
        !matches!(first, Err(RequestError::RateLimitedLocal(_))),
        "first request within rps must not be rate-limited"
    );

    // Second immediate dispatch is throttled before the provider.
    let second = run_dispatch(&state, Some("tenant-1")).await;
    assert!(
        matches!(second, Err(RequestError::RateLimitedLocal(_))),
        "second immediate dispatch must hit the policy rps override"
    );
}

// (point 1 + 3) A `provider`-keyed policy must match the EFFECTIVE provider.
// anthropic (priority 1) is unregistered → skipped; dispatch falls back to
// openrouter, and the openrouter-keyed budget policy fires — proving the
// enforcement sees the real provider, not just the first mapping.
#[cfg(feature = "policies")]
#[tokio::test]
async fn dispatch_provider_keyed_policy_matches_effective_fallback_provider() {
    let config = provider_keyed_config("openrouter", "[policies.budget]\nmonthly_usd = 5.0");
    let called = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut registry = crate::providers::ProviderRegistry::new();
    // Only openrouter is registered → anthropic is skipped and openrouter is
    // the effective (fallback) provider.
    registry.insert_provider_for_test(
        "openrouter",
        Arc::new(CountingProvider {
            called: called.clone(),
        }),
    );
    let state = crate::server::test_app_state(config, registry);

    {
        let mut tracker = state.observability.spend_tracker.lock().await;
        tracker.record("openrouter", "alpha", 10.0); // over the 5.0 cap
    }

    let result = run_dispatch(&state, None).await;
    assert!(
        matches!(result, Err(RequestError::BudgetExceeded { .. })),
        "the openrouter-keyed budget policy must fire on the fallback provider"
    );
    assert!(
        !called.load(std::sync::atomic::Ordering::SeqCst),
        "openrouter must NOT be called once its budget policy blocks"
    );
}

// ── SLICE 4: HIT on the non-streaming dispatch path ──

/// Mock provider returning a non-streaming response that contains a `Bash`
/// tool_use block.
#[cfg(feature = "policies")]
struct ToolUseProvider;

#[cfg(feature = "policies")]
#[async_trait::async_trait]
impl crate::providers::LlmProvider for ToolUseProvider {
    async fn send_message(
        &self,
        _request: CanonicalRequest,
    ) -> Result<ProviderResponse, crate::providers::error::ProviderError> {
        Ok(serde_json::from_value(serde_json::json!({
            "id": "msg_1",
            "type": "message",
            "role": "assistant",
            "content": [
                { "type": "text", "text": "ok" },
                { "type": "tool_use", "id": "tu_1", "name": "Bash", "input": { "command": "ls" } }
            ],
            "model": "alpha",
            "stop_reason": "tool_use",
            "usage": { "input_tokens": 1, "output_tokens": 1 }
        }))
        .unwrap())
    }

    async fn send_message_stream(
        &self,
        _request: CanonicalRequest,
    ) -> Result<crate::providers::StreamResponse, crate::providers::error::ProviderError> {
        Err(crate::providers::error::ProviderError::ApiError {
            status: 400,
            message: "no stream".to_string(),
        })
    }

    async fn count_tokens(
        &self,
        _request: crate::models::CountTokensRequest,
    ) -> Result<crate::models::CountTokensResponse, crate::providers::error::ProviderError> {
        Err(crate::providers::error::ProviderError::ApiError {
            status: 400,
            message: "no count".to_string(),
        })
    }

    fn supports_model(&self, _model: &str) -> bool {
        true
    }
}

// Real dispatch(): a non-stream response carrying a denied tool_use must come
// back with that tool_use STRIPPED. Red if the HIT call is removed from
// dispatch_non_streaming.
#[cfg(feature = "policies")]
#[tokio::test]
async fn dispatch_non_stream_hit_deny_strips_tool_use_from_response() {
    use crate::models::{ContentBlock, KnownContentBlock};

    let toml = r#"
[server]
host = "127.0.0.1"
port = 18091

[router]
default = "alpha"

[[providers]]
name = "mock"
provider_type = "openai"
auth_type = "apikey"
api_key = "sk-test"
base_url = "http://127.0.0.1:1"
models = ["alpha"]

[[models]]
name = "alpha"
[[models.mappings]]
priority = 1
provider = "mock"
actual_model = "alpha"
"#;
    let config = crate::cli::AppConfig::from_content(toml, "hit_non_stream_test").expect("config");
    let mut registry = crate::providers::ProviderRegistry::new();
    registry.insert_provider_for_test("mock", Arc::new(ToolUseProvider));
    let state = crate::server::test_app_state(config, registry);

    // Resolved HIT policy denying Bash (as the handler would attach it).
    let hit: crate::features::policies::hit::HitOverride =
        serde_json::from_value(serde_json::json!({ "deny": ["Bash"] })).unwrap();
    let resolved = crate::features::policies::resolved::ResolvedPolicy {
        matched: true,
        hit: Some(hit),
        ..Default::default()
    };

    let inner = state.snapshot();
    let dlp: Option<Arc<DlpEngine>> = None;
    let headers = HeaderMap::new();
    let ctx = DispatchContext {
        state: &state,
        inner: &inner,
        dlp: &dlp,
        model: "alpha".to_string(),
        is_streaming: false,
        tenant_id: None,
        #[cfg(feature = "agents")]
        agent: crate::features::agents::AgentContext::default(),
        allowed_models: None,
        allowed_providers: Vec::new(),
        peer_ip: "127.0.0.1".to_string(),
        req_id: "req-dispatch-hit",
        start_time: std::time::Instant::now(),
        headers: &headers,
        trace_id: None,
        audited: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        resolved_policy: Some(resolved),
    };
    let mut request: CanonicalRequest = serde_json::from_value(serde_json::json!({
        "model": "alpha",
        "max_tokens": 16,
        "messages": [{ "role": "user", "content": "go" }]
    }))
    .unwrap();

    let result = dispatch(&ctx, &mut request).await.expect("dispatch ok");
    let DispatchResult::Complete { response, .. } = result else {
        panic!("expected a Complete result");
    };

    let has_tool_use = response
        .content
        .iter()
        .any(|b| matches!(b, ContentBlock::Known(KnownContentBlock::ToolUse { .. })));
    assert!(
        !has_tool_use,
        "the denied tool_use must be stripped from the non-stream response"
    );
    // The text block survives.
    assert!(response
        .content
        .iter()
        .any(|b| matches!(b, ContentBlock::Known(KnownContentBlock::Text { .. }))));
}

// ── SLICE 6: inbound tool validation wiring ──

/// Records the tool names of the request it receives, then fails fast.
struct ToolRecordingProvider {
    seen: Arc<std::sync::Mutex<Vec<String>>>,
}

#[async_trait::async_trait]
impl crate::providers::LlmProvider for ToolRecordingProvider {
    async fn send_message(
        &self,
        request: CanonicalRequest,
    ) -> Result<ProviderResponse, crate::providers::error::ProviderError> {
        let names = request
            .tools
            .as_ref()
            .map(|t| t.iter().filter_map(|t| t.name.clone()).collect())
            .unwrap_or_default();
        *self.seen.lock().unwrap() = names;
        Err(crate::providers::error::ProviderError::ApiError {
            status: 400,
            message: "recorded".to_string(),
        })
    }

    async fn send_message_stream(
        &self,
        _request: CanonicalRequest,
    ) -> Result<crate::providers::StreamResponse, crate::providers::error::ProviderError> {
        Err(crate::providers::error::ProviderError::ApiError {
            status: 400,
            message: "no stream".to_string(),
        })
    }

    async fn count_tokens(
        &self,
        _request: crate::models::CountTokensRequest,
    ) -> Result<crate::models::CountTokensResponse, crate::providers::error::ProviderError> {
        Err(crate::providers::error::ProviderError::ApiError {
            status: 400,
            message: "no count".to_string(),
        })
    }

    fn supports_model(&self, _model: &str) -> bool {
        true
    }
}

// Real dispatch(): a malformed inbound tool must be stripped (Step 1.55)
// BEFORE the provider is called, while the well-formed tool reaches it. Red
// if the tool-validation call is removed from dispatch.
#[tokio::test]
async fn dispatch_strips_malformed_inbound_tool_before_provider() {
    let toml = r#"
[server]
host = "127.0.0.1"
port = 18090

[router]
default = "alpha"

[[providers]]
name = "mock"
provider_type = "openai"
auth_type = "apikey"
api_key = "sk-test"
base_url = "http://127.0.0.1:1"
models = ["alpha"]

[[models]]
name = "alpha"
[[models.mappings]]
priority = 1
provider = "mock"
actual_model = "alpha"
"#;
    let config =
        crate::cli::AppConfig::from_content(toml, "tool_validation_dispatch").expect("config");
    let seen = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let mut registry = crate::providers::ProviderRegistry::new();
    registry.insert_provider_for_test(
        "mock",
        Arc::new(ToolRecordingProvider { seen: seen.clone() }),
    );
    let state = crate::server::test_app_state(config, registry);

    let inner = state.snapshot();
    let dlp: Option<Arc<DlpEngine>> = None;
    let headers = HeaderMap::new();
    let ctx = DispatchContext {
        state: &state,
        inner: &inner,
        dlp: &dlp,
        model: "alpha".to_string(),
        is_streaming: false,
        tenant_id: None,
        #[cfg(feature = "agents")]
        agent: crate::features::agents::AgentContext::default(),
        allowed_models: None,
        allowed_providers: Vec::new(),
        peer_ip: "127.0.0.1".to_string(),
        req_id: "req-toolval",
        start_time: std::time::Instant::now(),
        headers: &headers,
        trace_id: None,
        audited: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        #[cfg(feature = "policies")]
        resolved_policy: None,
    };
    // Two tools: one well-formed, one malformed (input_schema is a string).
    let mut request: CanonicalRequest = serde_json::from_value(serde_json::json!({
        "model": "alpha",
        "max_tokens": 16,
        "messages": [{ "role": "user", "content": "hi" }],
        "tools": [
            { "name": "good_tool", "input_schema": { "type": "object" } },
            { "name": "bad_tool", "input_schema": "not-a-schema" }
        ]
    }))
    .unwrap();

    let _ = dispatch(&ctx, &mut request).await;

    let received = seen.lock().unwrap().clone();
    assert!(
        received.contains(&"good_tool".to_string()),
        "the well-formed tool must reach the provider"
    );
    assert!(
        !received.contains(&"bad_tool".to_string()),
        "the malformed tool must be stripped before the provider; got {received:?}"
    );
}

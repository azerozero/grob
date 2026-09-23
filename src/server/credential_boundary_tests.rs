//! Regression tests at the HTTP, RPC, MCP and persistence boundaries.
use super::*;
use axum::{
    body::{to_bytes, Body},
    extract::ConnectInfo,
    http::{Request, StatusCode},
};
use secrecy::SecretString;
use serde_json::{json, Value};
use tower::ServiceExt;

fn fixture() -> (tempfile::TempDir, Arc<AppState>, axum::Router) {
    let home = tempfile::tempdir().unwrap();
    let text = r#"
[server]
host = "127.0.0.1"
[auth]
mode = "api_key"
api_key = "synthetic-admin"
adopt_from_system = false
[router]
default = "alpha"
think = "alpha"
background = "alpha"
[security]
enabled = false
[[providers]]
name = "mock"
provider_type = "openai"
models = ["alpha", "beta"]
api_key = "synthetic-primary"
headers = { X-Credential = "synthetic-header" }
base_url = "http://127.0.0.1:1"
[providers.pool]
keys = ["synthetic-pool"]
[[models]]
name = "alpha"
[[models.mappings]]
provider = "mock"
actual_model = "alpha"
priority = 1
[[models]]
name = "beta"
[[models.mappings]]
provider = "mock"
actual_model = "beta"
priority = 1
"#;
    let path = home.path().join("config.toml");
    std::fs::write(&path, text).unwrap();
    let config = AppConfig::from_content(text, "boundary-test").unwrap();
    #[allow(unused_mut)]
    let mut state = test_app_state_with_source(
        config.clone(),
        crate::providers::ProviderRegistry::new(),
        crate::cli::ConfigSource::File(path),
    );
    #[cfg(feature = "mcp")]
    {
        Arc::get_mut(&mut state).unwrap().security.mcp = Some(Arc::new(
            crate::features::mcp::McpState::new(Default::default(), Default::default()),
        ));
    }
    let app = build_app_router(&config, state.clone());
    (home, state, app)
}

async fn call(
    app: &axum::Router,
    path: &str,
    token: &str,
    body: Option<Value>,
    spoof: bool,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .uri(path)
        .method(if body.is_some() { "POST" } else { "GET" })
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"));
    if spoof {
        request = request.header("x-forwarded-for", "127.0.0.1");
    }
    let mut request = request
        .body(Body::from(body.map(|v| v.to_string()).unwrap_or_default()))
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:54321".parse::<std::net::SocketAddr>().unwrap(),
    ));
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1_000_000).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn rpc(method: &str, params: Value) -> Value {
    json!({"jsonrpc":"2.0", "id":1, "method":method, "params":params})
}

async fn agent(app: &axum::Router) -> String {
    let (status, created) = call(
        app,
        "/rpc",
        "synthetic-admin",
        Some(rpc("grob/keys/create", json!({"name":"agent"}))),
        false,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    created["result"]["secret"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn agent_cannot_escalate_on_http_rpc_or_mcp_even_from_loopback() {
    let (_home, state, app) = fixture();
    let token = agent(&app).await;
    for spoof in [false, true] {
        for method in [
            "grob/keys/create",
            "grob/config/set",
            "grob/config/reload",
            "grob/server/reload_config",
        ] {
            let (_, response) = call(
                &app,
                "/rpc",
                &token,
                Some(rpc(
                    method,
                    json!({"name":"escalated", "key":"router.default", "value":"beta"}),
                )),
                spoof,
            )
            .await;
            assert!(response.get("error").is_some(), "{method}: {response}");
        }
        for path in ["/api/config", "/api/config/reload", "/api/oauth/authorize"] {
            assert_eq!(
                call(
                    &app,
                    path,
                    &token,
                    Some(json!({"router":{"default":"beta"}})),
                    spoof
                )
                .await
                .0,
                StatusCode::FORBIDDEN
            );
        }
        #[cfg(feature = "mcp")]
        {
            let (_, response) = call(
                &app,
                "/mcp",
                &token,
                Some(rpc(
                    "grob_keys",
                    json!({"action":"create", "name":"escalated"}),
                )),
                spoof,
            )
            .await;
            assert_eq!(response["error"]["code"], -32002, "{response}");
        }
    }
    assert_eq!(state.snapshot().config.router.default, "alpha");
    assert_eq!(state.grob_store.list_virtual_keys().len(), 1);
    #[cfg(feature = "mcp")]
    {
        let (_, response) = call(
            &app,
            "/mcp",
            "synthetic-admin",
            Some(rpc(
                "grob_keys",
                json!({"action":"create", "name":"mcp-admin"}),
            )),
            false,
        )
        .await;
        assert!(response.get("result").is_some(), "{response}");
        assert_eq!(state.grob_store.list_virtual_keys().len(), 2);
    }
}

#[tokio::test]
async fn every_config_surface_redacts_nested_credentials() {
    let (_home, _state, app) = fixture();
    let token = agent(&app).await;
    let responses = [
        call(&app, "/api/config", &token, None, false).await.1,
        call(
            &app,
            "/rpc",
            &token,
            Some(rpc("grob/config/get", json!({}))),
            false,
        )
        .await
        .1,
        call(
            &app,
            "/rpc",
            &token,
            Some(rpc("grob/config/diff", json!({}))),
            false,
        )
        .await
        .1,
    ];
    for response in responses {
        assert!(!response.to_string().contains("synthetic-"), "{response}");
        assert!(response.to_string().contains("redacted"), "{response}");
    }
}

#[tokio::test]
async fn config_patch_preserves_omitted_fields_and_rejects_invalid_before_write() {
    let (_home, state, app) = fixture();
    let path = match &state.config_source {
        crate::cli::ConfigSource::File(path) => path,
        _ => unreachable!(),
    };
    assert_eq!(
        call(
            &app,
            "/api/config",
            "synthetic-admin",
            Some(json!({"router":{"default":"beta"}})),
            false
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        state.snapshot().config.router.think.as_deref(),
        Some("alpha")
    );
    assert_eq!(
        state.snapshot().config.router.background.as_deref(),
        Some("alpha")
    );
    assert_eq!(
        call(
            &app,
            "/api/config",
            "synthetic-admin",
            Some(json!({"router":{"think":null}})),
            false
        )
        .await
        .0,
        StatusCode::OK
    );
    assert!(state.snapshot().config.router.think.is_none());
    let before = std::fs::read(path).unwrap();
    for body in [
        json!({"router":{"default":12}}),
        json!({"router":{"auto_map_regex":"["}}),
        json!({"router":{"default":null}}),
    ] {
        assert!(
            call(&app, "/api/config", "synthetic-admin", Some(body), false)
                .await
                .0
                .is_client_error()
        );
        assert_eq!(std::fs::read(path).unwrap(), before);
        assert_eq!(state.snapshot().config.router.default, "beta");
    }
}

#[tokio::test]
async fn named_admin_credential_replaces_live_without_restarting_or_changing_agent_keys() {
    let (_home, state, _) = fixture();
    let mut config = state.snapshot().config.clone();
    config.auth.api_key = Some(SecretString::from("secret:admin"));
    state
        .grob_store
        .set_secret("admin", "synthetic-admin")
        .unwrap();
    *state.inner.write().unwrap() = Arc::new(ReloadableState::new(
        config.clone(),
        Router::new(config.clone()),
        Arc::new(crate::providers::ProviderRegistry::new()),
    ));
    let app = build_app_router(&config, state.clone());
    let agent = agent(&app).await;
    state
        .grob_store
        .set_secret("admin", "synthetic-replacement")
        .unwrap();
    assert_eq!(
        call(&app, "/api/config", "synthetic-admin", None, false)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&app, "/api/config", "synthetic-replacement", None, false)
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        call(&app, "/v1/models", &agent, None, false).await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn agent_key_stays_stable_while_upstream_credentials_change_for_every_provider() {
    for (provider_type, path, auth_header, prefix, response) in [
        (
            "openai",
            "/v1/chat/completions",
            "authorization",
            "Bearer ",
            json!({"id":"mock", "object":"chat.completion", "model":"alpha", "choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}),
        ),
        (
            "anthropic",
            "/v1/messages",
            "x-api-key",
            "",
            json!({"id":"mock", "type":"message", "role":"assistant", "model":"alpha", "content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}),
        ),
        (
            "gemini",
            "/models/alpha:generateContent",
            "x-goog-api-key",
            "",
            json!({"candidates":[{"content":{"parts":[{"text":"ok"}],"role":"model"},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":1,"candidatesTokenCount":1}}),
        ),
    ] {
        let mut backend = mockito::Server::new_async().await;
        let (_home, state, app) = fixture();
        let agent = agent(&app).await;
        state
            .grob_store
            .set_secret("upstream", "synthetic-first")
            .unwrap();
        state
            .grob_store
            .set_secret("header", "synthetic-header-first")
            .unwrap();
        let mut config = state.snapshot().config.clone();
        let provider = &mut config.providers[0];
        provider.provider_type = provider_type.into();
        provider.api_key = Some(SecretString::from("secret:upstream"));
        provider.base_url = Some(if provider_type == "openai" {
            format!("{}/v1", backend.url())
        } else {
            backend.url()
        });
        provider.pool = None;
        provider.headers = Some(std::collections::HashMap::from([(
            "X-Credential".into(),
            "secret:header".into(),
        )]));
        let secrets =
            crate::storage::secrets::build_backend(&config.secrets, state.grob_store.clone());
        let registry = crate::providers::ProviderRegistry::from_configs_with_models(
            &config.providers,
            secrets,
            Some(state.token_store.clone()),
            &config.models,
            &config.server.timeouts,
        )
        .unwrap();
        *state.inner.write().unwrap() = Arc::new(ReloadableState::new(
            config.clone(),
            Router::new(config),
            Arc::new(registry),
        ));
        for suffix in ["first", "second"] {
            state
                .grob_store
                .set_secret("upstream", &format!("synthetic-{suffix}"))
                .unwrap();
            state
                .grob_store
                .set_secret("header", &format!("synthetic-header-{suffix}"))
                .unwrap();
            let mock = backend
                .mock("POST", path)
                .match_header(auth_header, format!("{prefix}synthetic-{suffix}").as_str())
                .match_header(
                    "x-credential",
                    format!("synthetic-header-{suffix}").as_str(),
                )
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(response.to_string())
                .expect(1)
                .create_async()
                .await;
            let (status, body) = call(&app, "/v1/messages", &agent, Some(json!({"model":"alpha","max_tokens":20,"messages":[{"role":"user","content":"hello"}]})), false).await;
            assert_eq!(status, StatusCode::OK, "{provider_type}: {body}");
            mock.assert_async().await;
        }
        state.grob_store.remove_secret("upstream").unwrap();
        let no_leak = backend.mock("POST", path).expect(0).create_async().await;
        let (status, _) = call(&app, "/v1/messages", &agent, Some(json!({"model":"alpha","max_tokens":20,"messages":[{"role":"user","content":"hello"}]})), false).await;
        assert!(!status.is_success());
        no_leak.assert_async().await;
    }
}

#[tokio::test]
async fn rpc_config_rejects_invalid_regex_and_optional_value_without_publication() {
    let (home, state, app) = fixture();
    let before = state.snapshot();
    let disk = std::fs::read(home.path().join("config.toml")).unwrap();
    for (key, value) in [
        ("router.background_regex", json!("[")),
        ("router.background", json!(42)),
    ] {
        let (_, response) = call(
            &app,
            "/rpc",
            "synthetic-admin",
            Some(rpc("grob/config/set", json!({"key":key, "value":value}))),
            false,
        )
        .await;
        assert!(response.get("error").is_some(), "{key}: {response}");
        assert!(Arc::ptr_eq(&before, &state.snapshot()), "{key}");
        assert_eq!(
            std::fs::read(home.path().join("config.toml")).unwrap(),
            disk
        );
    }
}

#[tokio::test]
async fn failed_provider_rebuild_preserves_persisted_config_and_snapshot() {
    let (home, state, _app) = fixture();
    let before = state.snapshot();
    let disk = std::fs::read(home.path().join("config.toml")).unwrap();
    let mut candidate = before.config.clone();
    candidate.providers[0].provider_type = "unknown-provider-type".into();
    let error = super::config_guard::persist_and_reload(&state, &candidate)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("Unknown provider type"));
    assert!(Arc::ptr_eq(&before, &state.snapshot()));
    assert_eq!(
        std::fs::read(home.path().join("config.toml")).unwrap(),
        disk
    );
    assert!(!home.path().join("config.toml.backup").exists());
}

#[tokio::test]
async fn rpc_tool_changes_reach_the_next_provider_request() {
    let mut backend = mockito::Server::new_async().await;
    let (_home, state, app) = fixture();
    let agent = agent(&app).await;
    let mut config = state.snapshot().config.clone();
    config.providers[0].base_url = Some(format!("{}/v1", backend.url()));
    let secrets = crate::storage::secrets::build_backend(&config.secrets, state.grob_store.clone());
    let registry = crate::providers::ProviderRegistry::from_configs_with_models(
        &config.providers,
        secrets,
        Some(state.token_store.clone()),
        &config.models,
        &config.server.timeouts,
    )
    .unwrap();
    *state.inner.write().unwrap() = Arc::new(ReloadableState::new(
        config.clone(),
        Router::new(config),
        Arc::new(registry),
    ));
    for (action, expected_tools) in [("enable", true), ("disable", false)] {
        let (_, response) = call(
            &app,
            "/rpc",
            "synthetic-admin",
            Some(rpc(
                &format!("grob/tools/{action}"),
                json!({"tool":"web_search"}),
            )),
            false,
        )
        .await;
        assert!(response.get("error").is_none(), "{response}");
        let mock = backend
            .mock("POST", "/v1/chat/completions")
            .match_request(move |request| {
                let body: Value = serde_json::from_slice(request.body().unwrap()).unwrap();
                let has_tool = body["tools"].as_array().is_some_and(|tools| {
                    tools.iter().any(|tool| tool["function"]["name"] == "web_search")
                });
                has_tool == expected_tools
            })
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!({"id":"mock", "object":"chat.completion", "model":"alpha", "choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}).to_string())
            .expect(1)
            .create_async()
            .await;
        let (status, body) = call(&app, "/v1/messages", &agent, Some(json!({"model":"alpha","max_tokens":20,"messages":[{"role":"user","content":"hello"}]})), false).await;
        assert_eq!(status, StatusCode::OK, "{action}: {body}");
        mock.assert_async().await;
    }
}

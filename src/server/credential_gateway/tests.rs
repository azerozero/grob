use super::*;
use crate::credentials::{
    config::ServiceBinding,
    record::{Authority, Bundle, CredentialRecord},
};
use axum::{body::to_bytes, http::Request};
use tower::ServiceExt;

async fn fixture(
    origin: &str,
    injection: Injection,
) -> (
    tempfile::TempDir,
    Arc<AppState>,
    axum::Router,
    String,
    ServiceBinding,
) {
    let (home, state, app) = crate::server::credential_boundary_tests::fixture();
    let key = crate::server::credential_boundary_tests::agent(&app).await;
    let mut agent = state.grob_store.list_virtual_keys().remove(0);
    agent.tenant_id = "gateway-test".into();
    state.grob_store.store_virtual_key(&agent).unwrap();
    let binding = ServiceBinding {
        id: "service".into(),
        tenant: agent.tenant_id,
        agents: vec![format!("key:{}", agent.id)],
        origin: origin.into(),
        allowed_ips: vec!["127.0.0.1".parse().unwrap()],
        paths: vec!["/test".into()],
        methods: vec!["POST".into()],
        injection,
        expires_at: None,
        vault: None,
    };
    let mut config = state.snapshot().config.clone();
    config.credential_services = vec![binding.clone()];
    config.validate().unwrap();
    *state.inner.write().unwrap() = Arc::new(crate::server::ReloadableState::new(
        config.clone(),
        crate::server::Router::new(config.clone()),
        Arc::new(crate::providers::ProviderRegistry::new()),
    ));
    let app = crate::server::build_app_router(&config, state.clone());
    (home, state, app, key, binding)
}

async fn call(app: &axum::Router, key: &str, path: &str, method: &str) -> (StatusCode, String) {
    let request = Request::builder()
        .uri(path)
        .method(method)
        .header("authorization", format!("Bearer {key}"))
        .header("cookie", "caller-cookie")
        .header("x-forwarded-for", "127.0.0.1")
        .header("x-tenant-id", "spoof")
        .body(Body::from("request"))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    assert!(response.headers().get("set-cookie").is_none());
    let body = to_bytes(response.into_body(), 65536).await.unwrap();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

#[tokio::test]
async fn local_gateway_rotates_without_changing_agent_and_filters_echoes() {
    let mut upstream = mockito::Server::new_async().await;
    let (_home, state, app, key, binding) = fixture(&upstream.url(), Injection::Bearer).await;
    for token in ["synthetic-first", "synthetic-second"] {
        state
            .grob_store
            .credential_publish(
                CredentialRecord::provision(
                    &binding,
                    Authority::Local,
                    Some(Bundle {
                        token: token.into(),
                        username: String::new(),
                        password: String::new(),
                    }),
                    None,
                ),
                None,
            )
            .unwrap();
        let mock = upstream
            .mock("POST", "/test")
            .match_header("authorization", format!("Bearer {token}").as_str())
            .match_header("cookie", mockito::Matcher::Missing)
            .match_header("x-forwarded-for", mockito::Matcher::Missing)
            .match_header("x-tenant-id", mockito::Matcher::Missing)
            .with_header("set-cookie", token)
            .with_body(format!("echo Bearer {token} then {token}"))
            .create_async()
            .await;
        let (status, body) = call(&app, &key, "/v1/services/service/test", "POST").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body, "echo [redacted] then [redacted]");
        mock.assert_async().await;
    }
    state
        .grob_store
        .credential_revoke(&binding.tenant, &binding.id)
        .unwrap();
    assert_eq!(
        call(&app, &key, "/v1/services/service/test", "POST")
            .await
            .0,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn refuses_wrong_identity_paths_methods_and_redirects_before_leaking() {
    let mut upstream = mockito::Server::new_async().await;
    let mut other = mockito::Server::new_async().await;
    let (_home, state, app, key, binding) = fixture(
        &upstream.url(),
        Injection::Header {
            name: "x-service-key".into(),
        },
    )
    .await;
    state
        .grob_store
        .credential_publish(
            CredentialRecord::provision(
                &binding,
                Authority::Local,
                Some(Bundle {
                    token: "synthetic-key".into(),
                    username: String::new(),
                    password: String::new(),
                }),
                None,
            ),
            None,
        )
        .unwrap();
    let second = crate::server::credential_boundary_tests::agent(&app).await;
    let no_calls = upstream
        .mock("POST", "/test")
        .expect(0)
        .create_async()
        .await;
    for (token, path, method) in [
        (second.as_str(), "/v1/services/service/test", "POST"),
        ("synthetic-admin", "/v1/services/service/test", "POST"),
        (key.as_str(), "/v1/services/service/test", "GET"),
        (key.as_str(), "/v1/services/service/other", "POST"),
        (key.as_str(), "/v1/services/service/%74est", "POST"),
        (
            key.as_str(),
            "/v1/services/service/test?url=https://evil.example",
            "POST",
        ),
    ] {
        assert_eq!(
            call(&app, token, path, method).await.0,
            StatusCode::FORBIDDEN
        );
    }
    no_calls.assert_async().await;
    no_calls.remove_async().await;
    let destination = other.mock("POST", "/test").expect(0).create_async().await;
    let redirect = upstream
        .mock("POST", "/test")
        .match_header("x-service-key", "synthetic-key")
        .with_status(307)
        .with_header("location", &format!("{}/test", other.url()))
        .create_async()
        .await;
    assert_eq!(
        call(&app, &key, "/v1/services/service/test", "POST")
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    redirect.assert_async().await;
    destination.assert_async().await;
}

#[tokio::test]
async fn basic_auth_uses_coherent_bundle_and_removes_encoded_echo() {
    let mut upstream = mockito::Server::new_async().await;
    let (_home, state, app, key, binding) = fixture(&upstream.url(), Injection::Basic).await;
    let encoded =
        base64::engine::general_purpose::STANDARD.encode("synthetic-user:synthetic-password");
    state
        .grob_store
        .credential_publish(
            CredentialRecord::provision(
                &binding,
                Authority::Local,
                Some(Bundle {
                    username: "synthetic-user".into(),
                    password: "synthetic-password".into(),
                    token: String::new(),
                }),
                None,
            ),
            None,
        )
        .unwrap();
    let mock = upstream
        .mock("POST", "/test")
        .match_header("authorization", format!("Basic {encoded}").as_str())
        .with_body(format!(
            "Basic {encoded} {encoded} synthetic-user synthetic-password"
        ))
        .create_async()
        .await;
    let (status, body) = call(&app, &key, "/v1/services/service/test", "POST").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "[redacted] [redacted] [redacted] [redacted]");
    mock.assert_async().await;
}

#[tokio::test]
async fn config_reload_requires_explicit_republication_and_status_never_exposes_values() {
    let mut upstream = mockito::Server::new_async().await;
    let (_home, state, app, key, binding) = fixture(&upstream.url(), Injection::Bearer).await;
    state
        .grob_store
        .credential_publish(
            CredentialRecord::provision(
                &binding,
                Authority::Local,
                Some(Bundle {
                    token: "synthetic-scoped-token".into(),
                    username: String::new(),
                    password: String::new(),
                }),
                None,
            ),
            None,
        )
        .unwrap();
    assert_eq!(
        call(&app, &key, "/api/credentials/status", "GET").await.0,
        StatusCode::FORBIDDEN
    );
    let (status, response) = call(&app, "synthetic-admin", "/api/credentials/status", "GET").await;
    assert_eq!(status, StatusCode::OK);
    assert!(!response.contains("synthetic-scoped-token"));
    let mut candidate = state.snapshot().config.clone();
    candidate.credential_services[0].methods.push("GET".into());
    crate::server::config_guard::persist_and_reload(&state, &candidate)
        .await
        .unwrap();
    let no_calls = upstream.mock("GET", "/test").expect(0).create_async().await;
    assert_eq!(
        call(&app, &key, "/v1/services/service/test", "GET").await.0,
        StatusCode::FORBIDDEN
    );
    no_calls.assert_async().await;
}

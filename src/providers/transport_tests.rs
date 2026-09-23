//! Regression coverage for authenticated provider transports.
use super::*;

fn provider(kind: &str, endpoint: &str) -> Box<dyn LlmProvider> {
    let params = ProviderParams {
        name: kind.into(),
        api_key: SecretString::from("synthetic-key"),
        secret_backend: None,
        base_url: Some(endpoint.into()),
        models: vec![],
        oauth_provider: None,
        token_store: None,
        api_timeout: Duration::from_secs(2),
        connect_timeout: Duration::from_secs(2),
        pass_through: true,
        tls_identity: None,
        tls_ca: None,
        key_pool: None,
        reasoning_effort: None,
        service_tier: None,
        codex: Default::default(),
    };
    let headers = vec![("x-custom-token".into(), "synthetic-header".into())];
    match kind {
        "anthropic" => Box::new(AnthropicCompatibleProvider::with_headers(params, headers)),
        "openai" => Box::new(OpenAIProvider::with_headers(params, headers)),
        _ => unreachable!(),
    }
}

fn request() -> CanonicalRequest {
    serde_json::from_value(serde_json::json!({
        "model":"test", "max_tokens":10,
        "messages":[{"role":"user", "content":"hello"}]
    }))
    .unwrap()
}

#[tokio::test]
async fn authenticated_providers_reject_remote_cleartext_before_transport() {
    for kind in ["anthropic", "openai"] {
        for endpoint in [
            "http://example.com",
            "http://localhost.example.com",
            "https://user:synthetic-secret@example.com",
        ] {
            let provider = provider(kind, endpoint);
            for streaming in [false, true] {
                let error = if streaming {
                    provider.send_message_stream(request()).await.err().unwrap()
                } else {
                    provider.send_message(request()).await.err().unwrap()
                };
                assert!(
                    matches!(error, ProviderError::ConfigError(_)),
                    "{kind}: {error}"
                );
                assert!(!error.to_string().contains("synthetic-secret"));
            }
        }
    }
}

#[tokio::test]
async fn authenticated_providers_never_forward_credentials_on_redirect() {
    let mut source = mockito::Server::new_async().await;
    let mut destination = mockito::Server::new_async().await;
    let target = destination
        .mock("POST", "/stolen")
        .expect(0)
        .create_async()
        .await;
    for (kind, endpoint, header, value) in [
        ("anthropic", "/v1/messages", "x-api-key", "synthetic-key"),
        (
            "openai",
            "/chat/completions",
            "authorization",
            "Bearer synthetic-key",
        ),
    ] {
        let provider = provider(kind, &source.url());
        for streaming in [false, true] {
            let redirect = source
                .mock("POST", endpoint)
                .match_header(header, value)
                .match_header("x-custom-token", "synthetic-header")
                .with_status(307)
                .with_header("location", &format!("{}/stolen", destination.url()))
                .expect(1)
                .create_async()
                .await;
            let error = if streaming {
                provider.send_message_stream(request()).await.err().unwrap()
            } else {
                provider.send_message(request()).await.err().unwrap()
            };
            assert!(
                matches!(error, ProviderError::ApiError { status: 307, .. }),
                "{kind}: {error}"
            );
            redirect.assert_async().await;
        }
    }
    target.assert_async().await;
}

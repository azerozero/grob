use super::*;

fn provider(base_url: &str) -> GeminiProvider {
    GeminiProvider::new(
        super::super::ProviderParams {
            name: "gemini-test".into(),
            api_key: SecretString::from("synthetic-key"),
            base_url: Some(base_url.into()),
            models: vec![],
            oauth_provider: None,
            token_store: None,
            api_timeout: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(5),
            pass_through: true,
            tls_identity: None,
            tls_ca: None,
            key_pool: None,
            reasoning_effort: None,
            service_tier: None,
            codex: Default::default(),
        },
        HashMap::new(),
        None,
        None,
    )
}

fn request() -> CanonicalRequest {
    serde_json::from_value(serde_json::json!({
        "model": "gemini-test", "max_tokens": 10,
        "messages": [{"role": "user", "content": "hello"}]
    }))
    .unwrap()
}

#[tokio::test]
async fn api_key_stays_out_of_urls_and_debug_output() {
    let provider = provider("https://generativelanguage.googleapis.com/v1beta");
    for streaming in [false, true] {
        let prepared = provider
            .prepare_request(&request(), streaming)
            .await
            .unwrap();
        let outgoing = provider.build_http_request(&prepared).build().unwrap();
        assert!(!outgoing.url().as_str().contains("synthetic-key"));
        assert!(!outgoing.url().query_pairs().any(|(key, _)| key == "key"));
        assert_eq!(outgoing.headers()["x-goog-api-key"], "synthetic-key");
        assert!(outgoing.headers()["x-goog-api-key"].is_sensitive());
        assert!(!format!("{outgoing:?}").contains("synthetic-key"));
        assert_eq!(outgoing.url().query(), streaming.then_some("alt=sse"));
    }
}

#[tokio::test]
async fn sends_header_auth_without_following_redirects_in_both_paths() {
    let mut source = mockito::Server::new_async().await;
    let mut destination = mockito::Server::new_async().await;
    let target = destination
        .mock("POST", "/stolen")
        .expect(0)
        .create_async()
        .await;
    let provider = provider(&source.url());
    for streaming in [false, true] {
        let (action, _) = GeminiProvider::url_parts(streaming);
        let redirect = source
            .mock("POST", format!("/models/gemini-test:{action}").as_str())
            .match_query(if streaming {
                mockito::Matcher::Exact("alt=sse".into())
            } else {
                mockito::Matcher::Missing
            })
            .match_header("x-goog-api-key", "synthetic-key")
            .with_status(307)
            .with_header("location", &format!("{}/stolen", destination.url()))
            .create_async()
            .await;
        let error = if streaming {
            provider.send_message_stream(request()).await.err().unwrap()
        } else {
            provider.send_message(request()).await.err().unwrap()
        };
        assert!(matches!(error, ProviderError::ApiError { status: 307, .. }));
        redirect.assert_async().await;
    }
    target.assert_async().await;
}

#[tokio::test]
async fn rejects_remote_cleartext_before_sending_credentials() {
    for endpoint in ["http://example.com", "http://localhost.example.com"] {
        let provider = provider(endpoint);
        for streaming in [false, true] {
            assert!(
                matches!(provider.prepare_request(&request(), streaming).await,
                Err(ProviderError::ConfigError(reason)) if reason.contains("require HTTPS"))
            );
        }
    }
}

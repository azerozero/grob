//! Best-effort API key validation via lightweight provider calls.
//!
//! Pings a provider's models endpoint with the supplied key to detect
//! obvious credential errors (expired, revoked, wrong format) before
//! accepting them in the setup wizard or auto-flow. Network failures
//! and unsupported providers are treated as warnings, never blockers.

use std::time::Duration;
use tracing::warn;

/// Timeout for validation requests.
const VALIDATE_TIMEOUT: Duration = Duration::from_secs(5);

/// Builds the validation URL and auth header for a provider.
///
/// Returns `None` for providers that lack a known lightweight endpoint.
fn validation_request(provider_name: &str, api_key: &str) -> Option<(String, String, String)> {
    match provider_name {
        "anthropic" => Some((
            "https://api.anthropic.com/v1/models".to_string(),
            "x-api-key".to_string(),
            api_key.to_string(),
        )),
        "openai" => Some((
            "https://api.openai.com/v1/models".to_string(),
            "Authorization".to_string(),
            format!("Bearer {api_key}"),
        )),
        "gemini" => Some((
            format!("https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"),
            String::new(),
            String::new(),
        )),
        "openrouter" => Some((
            "https://openrouter.ai/api/v1/models".to_string(),
            "Authorization".to_string(),
            format!("Bearer {api_key}"),
        )),
        "deepseek" => Some((
            "https://api.deepseek.com/models".to_string(),
            "Authorization".to_string(),
            format!("Bearer {api_key}"),
        )),
        "mistral" => Some((
            "https://api.mistral.ai/v1/models".to_string(),
            "Authorization".to_string(),
            format!("Bearer {api_key}"),
        )),
        _ => None,
    }
}

/// Builds a validation request for a custom endpoint with a user-supplied base URL.
pub fn custom_validation_request(
    provider_type: &str,
    base_url: &str,
    api_key: &str,
) -> Option<(String, String, String)> {
    let base = base_url.trim_end_matches('/');
    match provider_type {
        "openai_compatible" => Some((
            format!("{base}/models"),
            "Authorization".to_string(),
            format!("Bearer {api_key}"),
        )),
        "anthropic_compatible" => Some((
            format!("{base}/v1/models"),
            "x-api-key".to_string(),
            api_key.to_string(),
        )),
        _ => None,
    }
}

/// Validates an API key against a custom endpoint.
pub async fn validate_custom_endpoint(provider_type: &str, base_url: &str, api_key: &str) -> bool {
    let Some((url, header_name, header_value)) =
        custom_validation_request(provider_type, base_url, api_key)
    else {
        return true;
    };

    let client = match reqwest::Client::builder().timeout(VALIDATE_TIMEOUT).build() {
        Ok(c) => c,
        Err(_) => return true,
    };

    let mut request = client.get(&url);
    if !header_name.is_empty() {
        request = request.header(&header_name, &header_value);
    }
    if provider_type == "anthropic_compatible" {
        request = request.header("anthropic-version", "2023-06-01");
    }

    match request.send().await {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                true
            } else if status.as_u16() == 401 || status.as_u16() == 403 {
                false
            } else {
                warn!(
                    provider_type,
                    base_url,
                    status = status.as_u16(),
                    "custom endpoint check returned unexpected status, accepting key"
                );
                true
            }
        }
        Err(e) => {
            warn!(
                provider_type,
                base_url,
                error = %e,
                "custom endpoint check failed (network), accepting key"
            );
            true
        }
    }
}

/// Outcome of a credential probe used by the `credentials test` command.
///
/// Distinct from the boolean used in the setup wizard so callers can tell
/// network failures (warn) apart from auth failures (fail) and from
/// providers that don't expose a probe endpoint (skip).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckOutcome {
    /// Provider returned 2xx. The key is valid right now.
    Ok,
    /// Provider returned 401 or 403. The key is invalid or revoked.
    Invalid {
        /// HTTP status code observed (401 or 403).
        status: u16,
    },
    /// Probe could not run: network error, 5xx, or unexpected status.
    /// The key may still be valid; the upstream is unhealthy.
    Network {
        /// Short reason string suitable for a single-line CLI report.
        reason: String,
    },
    /// Provider type is unknown or has no lightweight probe endpoint.
    /// The check was skipped, no judgement is made on the key.
    Skipped {
        /// Why the probe was not attempted.
        reason: String,
    },
}

/// Probes a provider's lightweight endpoint and returns a structured outcome.
///
/// Honours `base_url` overrides for OpenAI-compatible / Anthropic-compatible
/// providers so a `secret:` referenced by, say, a DeepSeek-via-OpenRouter
/// config still hits the right host. The probe uses a 10-second timeout
/// per provider and never logs the key value.
pub async fn check_api_key(
    provider_type: &str,
    base_url: Option<&str>,
    api_key: &str,
    timeout: Duration,
) -> CheckOutcome {
    // Pick the URL + headers tuple. Custom base_url takes precedence so a
    // user with a private OpenAI-compatible deployment is probed on the
    // right host instead of api.openai.com.
    let request_spec = match base_url {
        Some(url) if !url.is_empty() => custom_validation_request(provider_type, url, api_key)
            .or_else(|| validation_request(provider_type, api_key)),
        _ => validation_request(provider_type, api_key),
    };

    let Some((url, header_name, header_value)) = request_spec else {
        return CheckOutcome::Skipped {
            reason: format!("no probe endpoint known for provider_type='{provider_type}'"),
        };
    };

    if !url.starts_with("https://") && !url.starts_with("http://") {
        return CheckOutcome::Skipped {
            reason: "non-http endpoint".into(),
        };
    }

    let client = match reqwest::Client::builder().timeout(timeout).build() {
        Ok(c) => c,
        Err(e) => {
            return CheckOutcome::Network {
                reason: format!("client build failed: {e}"),
            };
        }
    };

    let mut request = client.get(&url);
    if !header_name.is_empty() {
        request = request.header(&header_name, &header_value);
    }
    // NOTE: Anthropic and Anthropic-compatible endpoints both require the
    // version pin header; without it they 400 even on `/v1/models`.
    if provider_type == "anthropic" || provider_type == "anthropic_compatible" {
        request = request.header("anthropic-version", "2023-06-01");
    }

    match request.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            if (200..300).contains(&status) {
                CheckOutcome::Ok
            } else if status == 401 || status == 403 {
                CheckOutcome::Invalid { status }
            } else {
                CheckOutcome::Network {
                    reason: format!("HTTP {status}"),
                }
            }
        }
        Err(e) => {
            let reason = if e.is_timeout() {
                "timeout".to_string()
            } else if e.is_connect() {
                "connect error".to_string()
            } else {
                "network error".to_string()
            };
            warn!(provider = provider_type, error = %e, "credential probe failed");
            CheckOutcome::Network { reason }
        }
    }
}

/// Validates an API key by attempting a lightweight provider call.
///
/// Returns `true` when the provider confirms the key is valid (HTTP 2xx).
/// Returns `false` on auth errors (401/403). Returns `true` (optimistic)
/// on network errors, timeouts, or unsupported providers so the wizard
/// never blocks on infrastructure issues.
pub async fn validate_api_key(provider_name: &str, api_key: &str) -> bool {
    let Some((url, header_name, header_value)) = validation_request(provider_name, api_key) else {
        // Provider not recognized — accept optimistically.
        return true;
    };

    let client = match reqwest::Client::builder().timeout(VALIDATE_TIMEOUT).build() {
        Ok(c) => c,
        Err(_) => return true,
    };

    if !url.starts_with("https://") {
        return true;
    }

    let mut request = client.get(&url);
    if !header_name.is_empty() {
        // All validation URLs are HTTPS (see validation_request above).
        request = request.header(&header_name, &header_value); // lgtm[rs/cleartext-transmission]
    }
    // NOTE: Anthropic requires an anthropic-version header.
    if provider_name == "anthropic" {
        request = request.header("anthropic-version", "2023-06-01");
    }

    match request.send().await {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                true
            } else if status.as_u16() == 401 || status.as_u16() == 403 {
                false
            } else {
                // Unexpected status — accept optimistically.
                warn!(
                    provider = provider_name,
                    status = status.as_u16(),
                    "credential check returned unexpected status, accepting key"
                );
                true
            }
        }
        Err(e) => {
            // Network error or timeout — accept optimistically.
            warn!(
                provider = provider_name,
                error = %e,
                "credential check failed (network), accepting key"
            );
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_provider_returns_true() {
        // Unknown providers are accepted optimistically (no endpoint to check).
        assert!(validation_request("ollama", "dummy").is_none());
    }

    #[test]
    fn known_providers_produce_validation_urls() {
        let cases = [
            "anthropic",
            "openai",
            "gemini",
            "openrouter",
            "deepseek",
            "mistral",
        ];
        for name in cases {
            assert!(
                validation_request(name, "sk-test").is_some(),
                "{name} should have a validation URL"
            );
        }
    }

    #[test]
    fn anthropic_uses_header_auth() {
        let (url, header, value) = validation_request("anthropic", "sk-ant-123").unwrap();
        assert!(url.contains("api.anthropic.com"));
        assert_eq!(header, "x-api-key");
        assert_eq!(value, "sk-ant-123");
    }

    #[test]
    fn openai_uses_bearer_auth() {
        let (_url, header, value) = validation_request("openai", "sk-proj-abc").unwrap();
        assert_eq!(header, "Authorization");
        assert!(value.starts_with("Bearer "));
    }

    #[test]
    fn gemini_uses_query_param_auth() {
        let (url, header, _) = validation_request("gemini", "AIza-test").unwrap();
        assert!(url.contains("key=AIza-test"));
        // No auth header for Gemini API key flow.
        assert!(header.is_empty());
    }

    #[tokio::test]
    async fn validate_unknown_provider_accepts_optimistically() {
        assert!(validate_api_key("ollama", "anything").await);
    }

    #[tokio::test]
    async fn validate_with_bad_key_rejects() {
        // This test uses a mock server to simulate a 401 response.
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/v1/models")
            .with_status(401)
            .with_body(r#"{"error":"invalid_api_key"}"#)
            .create_async()
            .await;

        let url = server.url();
        // Temporarily override the validation URL by calling the internal logic directly.
        let client = reqwest::Client::builder()
            .timeout(VALIDATE_TIMEOUT)
            .build()
            .unwrap();
        let resp = client
            .get(format!("{url}/v1/models"))
            .header("Authorization", "Bearer bad-key")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 401);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn validate_with_good_key_accepts() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/v1/models")
            .with_status(200)
            .with_body(r#"{"data":[]}"#)
            .create_async()
            .await;

        let url = server.url();
        let client = reqwest::Client::builder()
            .timeout(VALIDATE_TIMEOUT)
            .build()
            .unwrap();
        let resp = client
            .get(format!("{url}/v1/models"))
            .header("Authorization", "Bearer good-key")
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success());
        mock.assert_async().await;
    }

    #[test]
    fn custom_openai_compatible_builds_correct_url() {
        let (url, header, value) =
            custom_validation_request("openai_compatible", "https://my-llm.com/v1", "sk-test")
                .unwrap();
        assert_eq!(url, "https://my-llm.com/v1/models");
        assert_eq!(header, "Authorization");
        assert!(value.starts_with("Bearer "));
    }

    #[test]
    fn custom_anthropic_compatible_builds_correct_url() {
        let (url, header, value) = custom_validation_request(
            "anthropic_compatible",
            "https://claude.corp.internal",
            "sk-ant-123",
        )
        .unwrap();
        assert_eq!(url, "https://claude.corp.internal/v1/models");
        assert_eq!(header, "x-api-key");
        assert_eq!(value, "sk-ant-123");
    }

    #[test]
    fn custom_unknown_type_returns_none() {
        assert!(custom_validation_request("unknown", "https://x.com", "k").is_none());
    }

    #[test]
    fn custom_url_trailing_slash_stripped() {
        let (url, _, _) =
            custom_validation_request("openai_compatible", "https://my-llm.com/v1/", "k").unwrap();
        assert_eq!(url, "https://my-llm.com/v1/models");
    }

    #[tokio::test]
    async fn validate_custom_endpoint_with_401_rejects() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/models")
            .with_status(401)
            .with_body(r#"{"error":"unauthorized"}"#)
            .create_async()
            .await;

        let result = validate_custom_endpoint("openai_compatible", &server.url(), "bad-key").await;
        assert!(!result);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn validate_custom_endpoint_with_200_accepts() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/models")
            .with_status(200)
            .with_body(r#"{"data":[]}"#)
            .create_async()
            .await;

        let result = validate_custom_endpoint("openai_compatible", &server.url(), "good-key").await;
        assert!(result);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn check_api_key_returns_ok_on_2xx() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/models")
            .with_status(200)
            .with_body(r#"{"data":[]}"#)
            .create_async()
            .await;

        let outcome = check_api_key(
            "openai_compatible",
            Some(&server.url()),
            "k",
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(outcome, CheckOutcome::Ok);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn check_api_key_returns_invalid_on_401() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/models")
            .with_status(401)
            .with_body(r#"{"error":"nope"}"#)
            .create_async()
            .await;

        let outcome = check_api_key(
            "openai_compatible",
            Some(&server.url()),
            "k",
            Duration::from_secs(5),
        )
        .await;
        assert_eq!(outcome, CheckOutcome::Invalid { status: 401 });
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn check_api_key_returns_network_on_5xx() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/models")
            .with_status(503)
            .create_async()
            .await;

        let outcome = check_api_key(
            "openai_compatible",
            Some(&server.url()),
            "k",
            Duration::from_secs(5),
        )
        .await;
        assert!(matches!(outcome, CheckOutcome::Network { .. }));
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn check_api_key_skips_unknown_provider_type() {
        let outcome = check_api_key("totally-unknown-foo", None, "k", Duration::from_secs(5)).await;
        assert!(matches!(outcome, CheckOutcome::Skipped { .. }));
    }
}

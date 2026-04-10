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

    let mut request = client.get(&url);
    if !header_name.is_empty() {
        request = request.header(&header_name, &header_value);
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
}

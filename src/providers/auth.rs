use super::error::ProviderError;
use crate::auth::{OAuthClient, OAuthConfig, TokenStore};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

/// Resolve an OAuth access token (with automatic refresh) or fall back to an API key.
///
/// This is the shared authentication logic used by all providers:
/// - Anthropic calls with `OAuthConfig::anthropic`
/// - OpenAI calls with `OAuthConfig::openai_codex`
/// - Gemini calls with `OAuthConfig::gemini`
pub async fn resolve_access_token(
    oauth_provider_id: Option<&str>,
    token_store: Option<&TokenStore>,
    oauth_config_fn: fn() -> OAuthConfig,
    api_key_fallback: &str,
) -> Result<Zeroizing<String>, ProviderError> {
    if let Some(oauth_provider_id) = oauth_provider_id {
        let token_store = token_store.ok_or_else(|| {
            ProviderError::AuthError(
                "OAuth provider configured but TokenStore not available".to_string(),
            )
        })?;

        let token = token_store.get(oauth_provider_id).ok_or_else(|| {
            ProviderError::AuthError(format!(
                "OAuth provider '{}' configured but no token found in store",
                oauth_provider_id
            ))
        })?;

        if token.needs_refresh() {
            tracing::info!(
                "🔄 Token for '{}' needs refresh, refreshing...",
                oauth_provider_id
            );
            let oauth_client = OAuthClient::new(oauth_config_fn(), token_store.clone());
            match oauth_client.refresh_token(oauth_provider_id).await {
                Ok(new_token) => {
                    tracing::info!("✅ Token refreshed successfully");
                    Ok(Zeroizing::new(
                        new_token.access_token.expose_secret().to_string(),
                    ))
                }
                Err(e) => {
                    tracing::error!("❌ Failed to refresh token: {}", e);
                    Err(ProviderError::AuthError(format!(
                        "Failed to refresh OAuth token: {}",
                        e
                    )))
                }
            }
        } else {
            Ok(Zeroizing::new(
                token.access_token.expose_secret().to_string(),
            ))
        }
    } else {
        Ok(Zeroizing::new(api_key_fallback.to_string()))
    }
}

/// Resolves a named API credential just before transport, with no plaintext cache.
pub(crate) fn resolve_api_key(
    reference: &str,
    backend: Option<&dyn crate::storage::secrets::SecretBackend>,
) -> Result<SecretString, ProviderError> {
    match reference.strip_prefix("secret:") {
        Some(name) => backend
            .and_then(|backend| backend.get(crate::storage::DEFAULT_TENANT, name))
            .ok_or_else(|| {
                ProviderError::AuthError(
                    "Named provider credential is missing or unreadable".into(),
                )
            }),
        None => Ok(SecretString::from(reference)),
    }
}

/// Resolves custom header credentials and marks their values sensitive to logging.
pub(crate) fn resolve_headers<'a>(
    headers: impl IntoIterator<Item = (&'a String, &'a String)>,
    backend: Option<&dyn crate::storage::secrets::SecretBackend>,
) -> Result<reqwest::header::HeaderMap, ProviderError> {
    let mut result = reqwest::header::HeaderMap::new();
    for (name, reference) in headers {
        let secret = resolve_api_key(reference, backend)?;
        let name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| ProviderError::ConfigError("Invalid custom header name".into()))?;
        let mut value = reqwest::header::HeaderValue::from_str(secret.expose_secret())
            .map_err(|_| ProviderError::ConfigError("Invalid custom header value".into()))?;
        value.set_sensitive(true);
        result.insert(name, value);
    }
    Ok(result)
}

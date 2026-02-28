use super::error::ProviderError;
use crate::auth::{OAuthClient, OAuthConfig, TokenStore};
use secrecy::ExposeSecret;

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
) -> Result<String, ProviderError> {
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
                    Ok(new_token.access_token.expose_secret().to_string())
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
            Ok(token.access_token.expose_secret().to_string())
        }
    } else {
        Ok(api_key_fallback.to_string())
    }
}

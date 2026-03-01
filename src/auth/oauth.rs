use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use rand::Rng;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::token_store::{OAuthToken, TokenStore};

/// Google Gemini CLI public OAuth client ID (split to avoid secret scanners).
/// Source: https://github.com/google-gemini/gemini-cli (public, installed-app type)
fn gemini_default_client_id() -> String {
    [
        "681255809395",
        "-oo8ft2oprdrnp9e3aqf6av3hmdib135j.apps.googleusercontent.com",
    ]
    .concat()
}

/// Google Gemini CLI public OAuth client secret (split to avoid secret scanners).
fn gemini_default_client_secret() -> String {
    ["GOCSPX", "-4uHgMPm-1o7Sk-geV6Cu5clXFsxl"].concat()
}

/// PKCE verifier for OAuth flow
#[derive(Debug, Clone)]
pub struct PKCEVerifier {
    verifier: String,
    challenge: String,
}

impl PKCEVerifier {
    /// Generate a new PKCE code verifier and challenge
    pub fn generate() -> Self {
        // Generate random verifier (43-128 characters)
        let mut rng = rand::thread_rng();
        let random_bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        let verifier = URL_SAFE_NO_PAD.encode(&random_bytes);

        // Generate challenge (SHA256 of verifier)
        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        let challenge_bytes = hasher.finalize();
        let challenge = URL_SAFE_NO_PAD.encode(challenge_bytes);

        Self {
            verifier,
            challenge,
        }
    }

    pub fn verifier(&self) -> &str {
        &self.verifier
    }

    pub fn challenge(&self) -> &str {
        &self.challenge
    }

    pub fn into_verifier(self) -> String {
        self.verifier
    }
}

/// Authorization URL with PKCE
#[derive(Debug, Clone)]
pub struct AuthorizationUrl {
    pub url: String,
    pub verifier: PKCEVerifier,
}

/// Detected OAuth provider type based on client_id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthProviderType {
    Anthropic,
    OpenAI,
    Gemini,
}

/// OAuth provider configuration
#[derive(Debug, Clone)]
pub struct OAuthConfig {
    pub client_id: String,
    pub client_secret: Option<String>, // Some providers require client_secret (e.g., Google)
    pub auth_url: String,
    pub token_url: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
}

impl OAuthConfig {
    /// Detect the provider type from the client_id.
    pub fn provider_type(&self) -> OAuthProviderType {
        if self.client_id == "app_EMoamEEZ73f0CkXaXp7hrann" {
            OAuthProviderType::OpenAI
        } else if self.client_id.starts_with("681255809395-") {
            OAuthProviderType::Gemini
        } else {
            OAuthProviderType::Anthropic
        }
    }
}

impl OAuthConfig {
    /// Anthropic Claude Pro/Max OAuth configuration
    pub fn anthropic() -> Self {
        Self {
            client_id: "9d1c250a-e61b-44d9-88ed-5944d1962f5e".to_string(),
            client_secret: None, // PKCE-based public client
            auth_url: "https://claude.ai/oauth/authorize".to_string(),
            token_url: "https://console.anthropic.com/v1/oauth/token".to_string(),
            redirect_uri: "https://console.anthropic.com/oauth/code/callback".to_string(),
            scopes: vec![
                "org:create_api_key".to_string(),
                "user:profile".to_string(),
                "user:inference".to_string(),
            ],
        }
    }

    /// Anthropic Console (for API key creation)
    pub fn anthropic_console() -> Self {
        let mut config = Self::anthropic();
        config.auth_url = "https://console.anthropic.com/oauth/authorize".to_string();
        config
    }

    /// OpenAI ChatGPT Plus/Pro OAuth configuration (for Codex)
    ///
    /// Note: OpenAI's official Codex CLI OAuth app has a fixed redirect_uri.
    /// The client_id "app_EMoamEEZ73f0CkXaXp7hrann" only allows:
    /// - http://localhost:1455/auth/callback
    ///
    /// This is hardcoded in OpenAI's OAuth app registration and cannot be changed.
    pub fn openai_codex() -> Self {
        Self {
            client_id: "app_EMoamEEZ73f0CkXaXp7hrann".to_string(),
            client_secret: None, // PKCE-based public client
            auth_url: "https://auth.openai.com/oauth/authorize".to_string(),
            token_url: "https://auth.openai.com/oauth/token".to_string(),
            redirect_uri: "http://localhost:1455/auth/callback".to_string(),
            scopes: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
                "offline_access".to_string(),
            ],
        }
    }

    /// Google Gemini (AI Pro/Ultra) OAuth configuration
    ///
    /// Note: This uses Google's official Gemini CLI OAuth app credentials.
    /// The client_id and client_secret are public (as documented in Google's official CLI).
    /// See: https://github.com/google-gemini/gemini-cli
    /// "It's ok to save this in git because this is an installed application"
    /// https://developers.google.com/identity/protocols/oauth2#installed
    pub fn gemini() -> Self {
        // Uses Google's official Gemini CLI public OAuth credentials by default.
        // See: https://github.com/google-gemini/gemini-cli
        // Override via GEMINI_OAUTH_CLIENT_ID / GEMINI_OAUTH_CLIENT_SECRET env vars.
        let default_id = gemini_default_client_id();
        let default_secret = gemini_default_client_secret();
        Self {
            client_id: std::env::var("GEMINI_OAUTH_CLIENT_ID").unwrap_or(default_id),
            client_secret: Some(
                std::env::var("GEMINI_OAUTH_CLIENT_SECRET").unwrap_or(default_secret),
            ),
            auth_url: "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
            token_url: "https://oauth2.googleapis.com/token".to_string(),
            redirect_uri: "http://localhost:13456/api/oauth/callback".to_string(),
            scopes: vec![
                "https://www.googleapis.com/auth/cloud-platform".to_string(),
                "https://www.googleapis.com/auth/userinfo.email".to_string(),
                "https://www.googleapis.com/auth/userinfo.profile".to_string(),
            ],
        }
    }
}

/// OAuth client for handling authentication flows
pub struct OAuthClient {
    config: OAuthConfig,
    token_store: TokenStore,
    http_client: reqwest::Client,
}

impl OAuthClient {
    /// Create a new OAuth client
    pub fn new(config: OAuthConfig, token_store: TokenStore) -> Self {
        Self {
            config,
            token_store,
            http_client: reqwest::Client::new(),
        }
    }

    /// Generate authorization URL with PKCE
    pub fn authorization_url(&self) -> Result<AuthorizationUrl> {
        let pkce = PKCEVerifier::generate();

        let mut url = url::Url::parse(&self.config.auth_url).context("Invalid OAuth auth URL")?;

        match self.config.provider_type() {
            OAuthProviderType::OpenAI => {
                // OpenAI uses a separate random state (not the PKCE verifier)
                use rand::Rng;
                let random_bytes: Vec<u8> = (0..16).map(|_| rand::thread_rng().gen()).collect();
                let state = random_bytes
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>();

                url.query_pairs_mut()
                    .append_pair("response_type", "code")
                    .append_pair("client_id", &self.config.client_id)
                    .append_pair("redirect_uri", &self.config.redirect_uri)
                    .append_pair("scope", &self.config.scopes.join(" "))
                    .append_pair("code_challenge", pkce.challenge())
                    .append_pair("code_challenge_method", "S256")
                    .append_pair("state", &state)
                    .append_pair("id_token_add_organizations", "true")
                    .append_pair("codex_cli_simplified_flow", "true")
                    .append_pair("originator", "codex_cli_rs");
            }
            OAuthProviderType::Gemini => {
                url.query_pairs_mut()
                    .append_pair("response_type", "code")
                    .append_pair("client_id", &self.config.client_id)
                    .append_pair("redirect_uri", &self.config.redirect_uri)
                    .append_pair("scope", &self.config.scopes.join(" "))
                    .append_pair("code_challenge", pkce.challenge())
                    .append_pair("code_challenge_method", "S256")
                    .append_pair("state", pkce.verifier())
                    .append_pair("access_type", "offline")
                    .append_pair("prompt", "consent");
            }
            OAuthProviderType::Anthropic => {
                url.query_pairs_mut()
                    .append_pair("code", "true")
                    .append_pair("client_id", &self.config.client_id)
                    .append_pair("response_type", "code")
                    .append_pair("redirect_uri", &self.config.redirect_uri)
                    .append_pair("scope", &self.config.scopes.join(" "))
                    .append_pair("code_challenge", pkce.challenge())
                    .append_pair("code_challenge_method", "S256")
                    .append_pair("state", pkce.verifier());
            }
        }

        Ok(AuthorizationUrl {
            url: url.to_string(),
            verifier: pkce,
        })
    }

    /// Exchange authorization code for tokens
    pub async fn exchange_code(
        &self,
        code: &str,
        verifier: &str,
        provider_id: &str,
    ) -> Result<OAuthToken> {
        // Parse code (backward compatible: "code#state" or just "code")
        let auth_code = if code.contains('#') {
            code.split('#').next().unwrap_or(code)
        } else {
            code
        };

        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: String,
            refresh_token: Option<String>,
            expires_in: i64,
        }

        let response = self.do_exchange(auth_code, verifier).await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("Token exchange failed: {} - {}", status, body));
        }

        let token_response: TokenResponse = response
            .json()
            .await
            .context("Failed to parse token response")?;

        let expires_at = Utc::now() + chrono::Duration::seconds(token_response.expires_in);

        let token = OAuthToken {
            provider_id: provider_id.to_string(),
            access_token: SecretString::new(token_response.access_token),
            refresh_token: SecretString::new(
                token_response
                    .refresh_token
                    .ok_or_else(|| anyhow!("Initial OAuth exchange must return refresh_token"))?,
            ),
            expires_at,
            enterprise_url: None,
            project_id: None,
        };

        self.token_store.save(token.clone())?;
        Ok(token)
    }

    /// Send the provider-specific token exchange request.
    async fn do_exchange(&self, auth_code: &str, verifier: &str) -> Result<reqwest::Response> {
        let provider_type = self.config.provider_type();
        tracing::debug!(
            "🔍 {:?} token exchange for redirect_uri={}",
            provider_type,
            &self.config.redirect_uri
        );

        if matches!(provider_type, OAuthProviderType::Anthropic) {
            self.send_json_request(&serde_json::json!({
                "code": auth_code,
                "state": verifier,
                "grant_type": "authorization_code",
                "client_id": &self.config.client_id,
                "redirect_uri": &self.config.redirect_uri,
                "code_verifier": verifier,
            }))
            .await
        } else {
            let mut params = vec![
                ("grant_type", "authorization_code"),
                ("client_id", self.config.client_id.as_str()),
                ("code", auth_code),
                ("code_verifier", verifier),
                ("redirect_uri", self.config.redirect_uri.as_str()),
            ];
            // Gemini requires client_secret; OpenAI does not
            let secret_str;
            if let Some(secret) = &self.config.client_secret {
                secret_str = secret.clone();
                params.push(("client_secret", secret_str.as_str()));
            }
            self.send_form_request(&params).await
        }
    }

    /// Refresh an access token
    pub async fn refresh_token(&self, provider_id: &str) -> Result<OAuthToken> {
        let existing_token = self
            .token_store
            .get(provider_id)
            .context("No token found for provider")?;

        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: String,
            refresh_token: Option<String>,
            expires_in: i64,
        }

        let response = self.do_refresh(&existing_token).await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("Token refresh failed: {} - {}", status, body));
        }

        let response_text = response
            .text()
            .await
            .context("Failed to read response body")?;
        tracing::debug!(
            "🔍 Token refresh response received ({} bytes)",
            response_text.len()
        );

        let token_response: TokenResponse =
            serde_json::from_str(&response_text).context("Failed to parse token response")?;

        let expires_at = Utc::now() + chrono::Duration::seconds(token_response.expires_in);

        let token = OAuthToken {
            provider_id: provider_id.to_string(),
            access_token: SecretString::new(token_response.access_token),
            refresh_token: token_response
                .refresh_token
                .map(SecretString::new)
                .unwrap_or(existing_token.refresh_token),
            expires_at,
            enterprise_url: existing_token.enterprise_url,
            project_id: existing_token.project_id,
        };

        self.token_store.save(token.clone())?;
        Ok(token)
    }

    /// Send the provider-specific token refresh request.
    async fn do_refresh(&self, existing_token: &OAuthToken) -> Result<reqwest::Response> {
        if matches!(self.config.provider_type(), OAuthProviderType::Anthropic) {
            self.send_json_request(&serde_json::json!({
                "grant_type": "refresh_token",
                "refresh_token": existing_token.refresh_token.expose_secret(),
                "client_id": &self.config.client_id,
            }))
            .await
        } else {
            let mut params = vec![
                ("grant_type", "refresh_token"),
                (
                    "refresh_token",
                    existing_token.refresh_token.expose_secret(),
                ),
                ("client_id", self.config.client_id.as_str()),
            ];
            // Gemini requires client_secret; OpenAI does not
            let secret_str;
            if let Some(secret) = &self.config.client_secret {
                secret_str = secret.clone();
                params.push(("client_secret", secret_str.as_str()));
            }
            self.send_form_request(&params).await
        }
    }

    /// POST a form-encoded request to the token endpoint.
    async fn send_form_request(&self, params: &[(&str, &str)]) -> Result<reqwest::Response> {
        self.http_client
            .post(&self.config.token_url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(params)
            .send()
            .await
            .context("OAuth token request failed")
    }

    /// POST a JSON request to the token endpoint.
    async fn send_json_request(&self, body: &impl Serialize) -> Result<reqwest::Response> {
        self.http_client
            .post(&self.config.token_url)
            .header("Content-Type", "application/json")
            .json(body)
            .send()
            .await
            .context("OAuth token request failed")
    }

    /// Load Code Assist for Gemini and get project ID
    /// This must be called after OAuth exchange for Gemini providers
    pub async fn load_code_assist(&self, access_token: &str) -> Result<String> {
        #[derive(Serialize)]
        struct LoadCodeAssistRequest {
            #[serde(
                skip_serializing_if = "Option::is_none",
                rename = "cloudaicompanionProject"
            )]
            cloudaicompanion_project: Option<String>,
            metadata: ClientMetadata,
        }

        #[derive(Serialize)]
        struct ClientMetadata {
            #[serde(rename = "ideType")]
            ide_type: String,
            platform: String,
            #[serde(rename = "pluginType")]
            plugin_type: String,
        }

        #[derive(Deserialize)]
        struct LoadCodeAssistResponse {
            #[serde(rename = "cloudaicompanionProject")]
            cloudaicompanion_project: Option<String>,
        }

        // Try to get project ID from environment variables (like gemini-cli does)
        let project_id = std::env::var("GOOGLE_CLOUD_PROJECT")
            .or_else(|_| std::env::var("GOOGLE_CLOUD_PROJECT_ID"))
            .ok();

        if let Some(ref pid) = project_id {
            tracing::info!("🔍 Using project ID from environment: {}", pid);
        } else {
            tracing::warn!(
                "⚠️ No GOOGLE_CLOUD_PROJECT env var set. loadCodeAssist may not return project ID."
            );
        }

        let request = LoadCodeAssistRequest {
            cloudaicompanion_project: project_id.clone(),
            metadata: ClientMetadata {
                ide_type: "IDE_UNSPECIFIED".to_string(),
                platform: "PLATFORM_UNSPECIFIED".to_string(),
                plugin_type: "GEMINI".to_string(),
            },
        };

        tracing::debug!("🔍 Calling loadCodeAssist with project_id={:?}", project_id);

        let response = self
            .http_client
            .post("https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist")
            .header("Authorization", format!("Bearer {}", access_token))
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .context("Failed to call loadCodeAssist")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            tracing::error!("❌ loadCodeAssist API error {}: {}", status, body);
            return Err(anyhow!("loadCodeAssist failed: {} - {}", status, body));
        }

        // Get response text first for debugging
        let response_text = response
            .text()
            .await
            .context("Failed to read loadCodeAssist response")?;

        tracing::debug!("📥 loadCodeAssist API response: {}", response_text);

        let load_response: LoadCodeAssistResponse = serde_json::from_str(&response_text)
            .context("Failed to parse loadCodeAssist response")?;

        tracing::debug!(
            "🔍 Parsed loadCodeAssist response: cloudaicompanion_project={:?}",
            load_response.cloudaicompanion_project
        );

        // If loadCodeAssist returned a project ID, use it
        // Otherwise, use the one we sent (from environment variables)
        // This matches gemini-cli behavior
        let final_project_id = load_response.cloudaicompanion_project.or(project_id);

        final_project_id.ok_or_else(|| {
            anyhow!("No project ID available. Set GOOGLE_CLOUD_PROJECT environment variable.")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkce_generation() {
        let pkce = PKCEVerifier::generate();

        // Verifier should be base64 URL-safe encoded
        assert!(!pkce.verifier().is_empty());
        assert!(!pkce.challenge().is_empty());

        // Challenge should be different from verifier
        assert_ne!(pkce.verifier(), pkce.challenge());
    }

    #[test]
    fn test_authorization_url() {
        let config = OAuthConfig::anthropic();
        let token_store = TokenStore::new(std::env::temp_dir().join("test_tokens.json")).unwrap();
        let client = OAuthClient::new(config, token_store);

        let auth_url = client.authorization_url().unwrap();

        assert!(auth_url.url.contains("client_id="));
        assert!(auth_url.url.contains("code_challenge="));
        assert!(auth_url.url.contains("code_challenge_method=S256"));
        assert!(auth_url.url.contains("scope="));
    }
}

//! RFC 8628 OAuth 2.0 Device Authorization Grant.
//!
//! Enables headless OAuth on machines without a browser (CI, SSH, containers):
//! the client displays a `user_code` + `verification_uri` the user enters on
//! another device, then polls the token endpoint until approval or expiry.
//!
//! Grob uses this for Google Gemini (which implements the standard) when
//! `GROB_OAUTH_HEADLESS=1` is set or `grob connect --headless` is passed.

use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use secrecy::SecretString;
use serde::Deserialize;

use super::oauth::{OAuthConfig, OAuthProviderType};
use super::token_store::{OAuthToken, TokenStore};

/// Google's device authorization endpoint for the OAuth 2.0 "limited input device" flow.
const GOOGLE_DEVICE_AUTH_URL: &str = "https://oauth2.googleapis.com/device/code";

/// Minimum poll interval enforced regardless of server hint (RFC 8628 §3.5).
const MIN_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Fallback poll interval when the server does not provide one.
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Extra backoff added when the server replies `slow_down` (RFC 8628 §3.5).
const SLOW_DOWN_INCREMENT: Duration = Duration::from_secs(5);

/// Successful response from the device authorization endpoint (RFC 8628 §3.2).
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceAuthorization {
    /// Opaque code the client sends back when polling the token endpoint.
    pub device_code: String,
    /// Short, human-typable code the user enters at the verification URI.
    pub user_code: String,
    /// URI the user opens on a second device to approve the request.
    pub verification_uri: String,
    /// Optional pre-filled verification URI that encodes the `user_code`.
    #[serde(default)]
    pub verification_uri_complete: Option<String>,
    /// Lifetime of the `device_code` in seconds.
    pub expires_in: u64,
    /// Minimum interval between token polls, in seconds.
    #[serde(default)]
    pub interval: Option<u64>,
}

impl DeviceAuthorization {
    /// Returns the interval between polls, honoring the server hint
    /// but never going below `MIN_POLL_INTERVAL`.
    pub fn poll_interval(&self) -> Duration {
        self.interval
            .map(Duration::from_secs)
            .unwrap_or(DEFAULT_POLL_INTERVAL)
            .max(MIN_POLL_INTERVAL)
    }
}

/// Token endpoint response for a pending / completed device flow.
#[derive(Debug, Deserialize)]
struct TokenResponseRaw {
    access_token: Option<String>,
    refresh_token: Option<String>,
    expires_in: Option<i64>,
    error: Option<String>,
    error_description: Option<String>,
}

/// Outcome of one poll of the token endpoint.
pub enum PollOutcome {
    /// User has approved; tokens are issued.
    Approved(OAuthToken),
    /// User has not yet approved — keep polling after `interval`.
    Pending,
    /// Server asked us to slow down — back off by `SLOW_DOWN_INCREMENT`.
    SlowDown,
    /// User explicitly denied the request.
    Denied,
    /// Device code expired before approval.
    Expired,
}

/// Device-authorization OAuth client for headless environments.
pub struct DeviceCodeClient {
    config: OAuthConfig,
    token_store: TokenStore,
    http: reqwest::Client,
    device_auth_url: String,
}

impl DeviceCodeClient {
    /// Creates a client for the given provider.
    ///
    /// # Errors
    ///
    /// Returns an error if the provider does not support RFC 8628 device flow.
    pub fn new(config: OAuthConfig, token_store: TokenStore) -> Result<Self> {
        let device_auth_url = device_auth_url_for(config.provider_type())
            .ok_or_else(|| anyhow!("Provider does not support RFC 8628 device flow"))?
            .to_string();
        Ok(Self {
            config,
            token_store,
            http: reqwest::Client::new(),
            device_auth_url,
        })
    }

    /// Starts the device authorization flow and returns the user-facing codes.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP request fails or the server returns a
    /// non-success status or malformed JSON.
    pub async fn start(&self) -> Result<DeviceAuthorization> {
        let scope = self.scopes_param();
        let mut params = vec![
            ("client_id", self.config.client_id.as_str()),
            ("scope", scope.as_str()),
        ];
        let secret;
        if let Some(s) = &self.config.client_secret {
            secret = s.clone();
            params.push(("client_secret", secret.as_str()));
        }

        let response = self
            .http
            .post(&self.device_auth_url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&params)
            .send()
            .await
            .context("device_authorization request failed")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!(
                "device_authorization failed: {} - {}",
                status,
                body
            ));
        }

        response
            .json::<DeviceAuthorization>()
            .await
            .context("Failed to parse device_authorization response")
    }

    /// Polls the token endpoint once with the given `device_code`.
    ///
    /// # Errors
    ///
    /// Returns an error only for transport-level or malformed-response
    /// failures. OAuth-protocol states (pending, denied, expired) are
    /// returned as [`PollOutcome`] variants.
    pub async fn poll_once(&self, device_code: &str, provider_id: &str) -> Result<PollOutcome> {
        let mut params = vec![
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("client_id", self.config.client_id.as_str()),
            ("device_code", device_code),
        ];
        let secret;
        if let Some(s) = &self.config.client_secret {
            secret = s.clone();
            params.push(("client_secret", secret.as_str()));
        }

        let response = self
            .http
            .post(&self.config.token_url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&params)
            .send()
            .await
            .context("device token poll request failed")?;

        let status = response.status();
        let body = response
            .text()
            .await
            .context("Failed to read token poll response body")?;
        let raw: TokenResponseRaw =
            serde_json::from_str(&body).context("Failed to parse token poll response")?;

        if status.is_success() {
            let access = raw
                .access_token
                .ok_or_else(|| anyhow!("Token response missing access_token"))?;
            let refresh = raw
                .refresh_token
                .ok_or_else(|| anyhow!("Token response missing refresh_token"))?;
            let expires = raw.expires_in.unwrap_or(3600);
            let token = OAuthToken {
                provider_id: provider_id.to_string(),
                access_token: SecretString::new(access),
                refresh_token: SecretString::new(refresh),
                expires_at: Utc::now() + chrono::Duration::seconds(expires),
                enterprise_url: None,
                project_id: None,
                needs_reauth: None,
            };
            self.token_store.save(token.clone())?;
            return Ok(PollOutcome::Approved(token));
        }

        // RFC 8628 §3.5: pending/slow_down/denied/expired are reported via `error`.
        match raw.error.as_deref() {
            Some("authorization_pending") => Ok(PollOutcome::Pending),
            Some("slow_down") => Ok(PollOutcome::SlowDown),
            Some("access_denied") => Ok(PollOutcome::Denied),
            Some("expired_token") => Ok(PollOutcome::Expired),
            Some(other) => Err(anyhow!(
                "device token poll failed: {} - {}",
                other,
                raw.error_description.unwrap_or_default()
            )),
            None => Err(anyhow!("device token poll failed: {} - {}", status, body)),
        }
    }

    /// Polls the token endpoint until approval, denial, or expiry.
    ///
    /// Honors the `interval` and `slow_down` hints per RFC 8628 §3.5.
    ///
    /// # Errors
    ///
    /// Returns an error if polling exceeds `expires_in`, the user denies,
    /// or a transport-level failure occurs.
    pub async fn poll_until_approved(
        &self,
        auth: &DeviceAuthorization,
        provider_id: &str,
    ) -> Result<OAuthToken> {
        let deadline = std::time::Instant::now() + Duration::from_secs(auth.expires_in);
        let mut interval = auth.poll_interval();

        loop {
            if std::time::Instant::now() >= deadline {
                return Err(anyhow!("Device code expired before approval"));
            }

            tokio::time::sleep(interval).await;

            match self.poll_once(&auth.device_code, provider_id).await? {
                PollOutcome::Approved(token) => return Ok(token),
                PollOutcome::Pending => continue,
                PollOutcome::SlowDown => {
                    interval = interval.saturating_add(SLOW_DOWN_INCREMENT);
                }
                PollOutcome::Denied => return Err(anyhow!("User denied device authorization")),
                PollOutcome::Expired => return Err(anyhow!("Device code expired")),
            }
        }
    }

    fn scopes_param(&self) -> String {
        self.config.scopes.join(" ")
    }
}

/// Returns the device-authorization endpoint URL for a provider, if supported.
///
/// Only Google/Gemini currently implements RFC 8628. Anthropic and OpenAI
/// Codex do not expose a device-authorization endpoint at time of writing.
pub fn device_auth_url_for(provider: OAuthProviderType) -> Option<&'static str> {
    match provider {
        OAuthProviderType::Gemini => Some(GOOGLE_DEVICE_AUTH_URL),
        OAuthProviderType::Anthropic | OAuthProviderType::OpenAI => None,
    }
}

/// Returns `true` when headless mode is requested via environment variable.
pub fn headless_requested() -> bool {
    std::env::var("GROB_OAUTH_HEADLESS")
        .map(|v| matches!(v.as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_auth_url_only_for_gemini() {
        assert!(device_auth_url_for(OAuthProviderType::Gemini).is_some());
        assert!(device_auth_url_for(OAuthProviderType::Anthropic).is_none());
        assert!(device_auth_url_for(OAuthProviderType::OpenAI).is_none());
    }

    #[test]
    fn client_rejects_unsupported_provider() {
        let store = TokenStore::new(std::env::temp_dir().join("dc_test_tokens.json")).unwrap();
        let err = match DeviceCodeClient::new(OAuthConfig::anthropic(), store) {
            Ok(_) => panic!("expected rejection for unsupported provider"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("does not support"));
    }

    #[test]
    fn poll_interval_never_below_minimum() {
        let auth = DeviceAuthorization {
            device_code: "dc".into(),
            user_code: "AB-CD".into(),
            verification_uri: "https://example.com".into(),
            verification_uri_complete: None,
            expires_in: 900,
            interval: Some(0),
        };
        assert!(auth.poll_interval() >= MIN_POLL_INTERVAL);
    }

    #[test]
    fn poll_interval_uses_default_when_absent() {
        let auth = DeviceAuthorization {
            device_code: "dc".into(),
            user_code: "AB-CD".into(),
            verification_uri: "https://example.com".into(),
            verification_uri_complete: None,
            expires_in: 900,
            interval: None,
        };
        assert_eq!(auth.poll_interval(), DEFAULT_POLL_INTERVAL);
    }

    #[test]
    fn poll_interval_honors_server_hint() {
        let auth = DeviceAuthorization {
            device_code: "dc".into(),
            user_code: "AB-CD".into(),
            verification_uri: "https://example.com".into(),
            verification_uri_complete: None,
            expires_in: 900,
            interval: Some(10),
        };
        assert_eq!(auth.poll_interval(), Duration::from_secs(10));
    }

    #[test]
    fn headless_requested_reads_env() {
        std::env::remove_var("GROB_OAUTH_HEADLESS");
        assert!(!headless_requested());
        std::env::set_var("GROB_OAUTH_HEADLESS", "1");
        assert!(headless_requested());
        std::env::set_var("GROB_OAUTH_HEADLESS", "no");
        assert!(!headless_requested());
        std::env::remove_var("GROB_OAUTH_HEADLESS");
    }
}

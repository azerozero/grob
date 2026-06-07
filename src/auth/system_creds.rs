//! Adoption of OAuth credentials from co-installed CLI tools.
//!
//! grob shares OAuth apps with the official Codex CLI (`~/.codex/auth.json`,
//! same OpenAI client id) and Claude Code (the macOS keychain item
//! `Claude Code-credentials`, same Anthropic client id). When enabled, grob can
//! mirror those tokens into its own [`TokenStore`] instead of running a separate
//! browser flow — and recover automatically when its own copy is revoked by
//! refresh-token rotation on the shared account.
//!
//! # Refresh ownership
//!
//! OpenAI and Anthropic rotate the `refresh_token` on every refresh, so two
//! independent holders of the same account's token invalidate each other. The
//! safe rule therefore differs per source (see [`grob_may_refresh`]): grob may
//! refresh an adopted Codex token (it becomes grob-private), but must treat an
//! adopted Claude token as a read-only mirror, because that keychain item is
//! shared by every Claude Code session on the host.

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, TimeZone, Utc};
use secrecy::SecretString;

use crate::auth::token_store::{OAuthToken, TokenStore};

/// macOS keychain service under which Claude Code stores its OAuth credential.
const CLAUDE_KEYCHAIN_SERVICE: &str = "Claude Code-credentials";

/// A co-installed CLI tool whose OAuth token grob can mirror.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemSource {
    /// Codex CLI / Codex.app — `~/.codex/auth.json`.
    Codex,
    /// Claude Code — macOS keychain item shared by all Claude Code sessions.
    ClaudeKeychain,
}

/// Returns the system credential source backing `provider_id`, if grob knows one.
///
/// The ids mirror [`crate::auth::refresh_daemon::config_for_provider_id`].
pub fn source_for(provider_id: &str) -> Option<SystemSource> {
    match provider_id {
        "openai-codex" => Some(SystemSource::Codex),
        "anthropic-max" | "claude-max" | "anthropic-oauth" => Some(SystemSource::ClaudeKeychain),
        _ => None,
    }
}

/// Reports whether grob may run its own refresh on a token adopted for `provider_id`.
///
/// Claude Code's keychain credential is shared by every Claude Code session on
/// the host. Refreshing it rotates the shared refresh token and signs them all
/// out, so grob mirrors it read-only and lets Claude Code own the refresh.
/// A Codex token becomes grob-private once adopted, so grob may refresh it.
pub fn grob_may_refresh(provider_id: &str) -> bool {
    !matches!(source_for(provider_id), Some(SystemSource::ClaudeKeychain))
}

/// Reads the current system token for `provider_id` into a grob [`OAuthToken`].
///
/// # Errors
///
/// Returns an error if grob has no system source for the provider, the source
/// is unreadable (missing file, keychain miss, non-macOS host), or the payload
/// cannot be parsed.
pub fn read_token(provider_id: &str) -> Result<OAuthToken> {
    match source_for(provider_id) {
        Some(SystemSource::Codex) => read_codex_token(provider_id),
        Some(SystemSource::ClaudeKeychain) => read_claude_token(provider_id),
        None => Err(anyhow!(
            "no system credential source known for provider '{provider_id}'"
        )),
    }
}

/// Mirrors the system token for `provider_id` into `store`, returning it.
///
/// # Errors
///
/// Returns an error if [`read_token`] fails or persisting to the store fails.
pub fn adopt(store: &TokenStore, provider_id: &str) -> Result<OAuthToken> {
    let token = read_token(provider_id)?;
    store.save(token.clone())?;
    Ok(token)
}

/// Reads and parses Codex CLI's `~/.codex/auth.json`.
fn read_codex_token(provider_id: &str) -> Result<OAuthToken> {
    let home = crate::home_dir().context("could not resolve home directory (set GROB_HOME)")?;
    let path = home.join(".codex").join("auth.json");
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("reading Codex auth file {}", path.display()))?;
    parse_codex_payload(provider_id, &raw)
}

/// Parses Codex CLI's `auth.json` body into an [`OAuthToken`].
///
/// The access token is a JWT whose `exp` claim sets `expires_at`; when it cannot
/// be decoded, a short fallback forces the refresh daemon to validate it soon.
fn parse_codex_payload(provider_id: &str, raw: &str) -> Result<OAuthToken> {
    let doc: serde_json::Value = serde_json::from_str(raw).context("parsing Codex auth.json")?;
    let tokens = doc
        .get("tokens")
        .context("Codex auth.json has no `tokens` object")?;
    let access = tokens
        .get("access_token")
        .and_then(|v| v.as_str())
        .context("Codex auth.json missing tokens.access_token")?;
    let refresh = tokens
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .context("Codex auth.json missing tokens.refresh_token")?;
    let expires_at = jwt_expiry(access).unwrap_or_else(|| Utc::now() + chrono::Duration::hours(1));
    Ok(OAuthToken {
        provider_id: provider_id.to_string(),
        access_token: SecretString::new(access.to_string()),
        refresh_token: SecretString::new(refresh.to_string()),
        expires_at,
        enterprise_url: None,
        project_id: None,
        needs_reauth: None,
    })
}

/// Reads Claude Code's OAuth credential from the macOS login keychain.
#[cfg(target_os = "macos")]
fn read_claude_token(provider_id: &str) -> Result<OAuthToken> {
    let output = std::process::Command::new("security")
        .args(["find-generic-password", "-s", CLAUDE_KEYCHAIN_SERVICE, "-w"])
        .output()
        .context("invoking macOS `security` to read the Claude Code keychain credential")?;
    if !output.status.success() {
        return Err(anyhow!(
            "Claude Code keychain item '{CLAUDE_KEYCHAIN_SERVICE}' not found (is Claude Code signed in?)"
        ));
    }
    let raw = String::from_utf8(output.stdout).context("Claude keychain payload is not UTF-8")?;
    parse_claude_payload(provider_id, raw.trim())
}

/// Stub for non-macOS hosts, where the Claude keychain is unavailable.
#[cfg(not(target_os = "macos"))]
fn read_claude_token(_provider_id: &str) -> Result<OAuthToken> {
    Err(anyhow!(
        "Claude Code credential adoption reads the macOS keychain and is only available on macOS"
    ))
}

/// Parses Claude Code's keychain JSON payload into an [`OAuthToken`].
///
/// `expiresAt` is a millisecond Unix timestamp; a missing or invalid value
/// falls back to a short window so the token is re-validated promptly.
fn parse_claude_payload(provider_id: &str, raw: &str) -> Result<OAuthToken> {
    let doc: serde_json::Value =
        serde_json::from_str(raw).context("parsing Claude keychain JSON")?;
    let oauth = doc
        .get("claudeAiOauth")
        .context("Claude keychain JSON has no `claudeAiOauth` object")?;
    let access = oauth
        .get("accessToken")
        .and_then(|v| v.as_str())
        .context("Claude keychain missing claudeAiOauth.accessToken")?;
    let refresh = oauth
        .get("refreshToken")
        .and_then(|v| v.as_str())
        .context("Claude keychain missing claudeAiOauth.refreshToken")?;
    let expires_at = oauth
        .get("expiresAt")
        .and_then(serde_json::Value::as_i64)
        .and_then(|ms| Utc.timestamp_millis_opt(ms).single())
        .unwrap_or_else(|| Utc::now() + chrono::Duration::hours(1));
    Ok(OAuthToken {
        provider_id: provider_id.to_string(),
        access_token: SecretString::new(access.to_string()),
        refresh_token: SecretString::new(refresh.to_string()),
        expires_at,
        enterprise_url: None,
        project_id: None,
        needs_reauth: None,
    })
}

/// Extracts the `exp` claim from a JWT as a UTC timestamp.
///
/// Decodes only the payload segment; the signature is not verified because the
/// upstream issued the token and grob merely mirrors its expiry.
fn jwt_expiry(jwt: &str) -> Option<DateTime<Utc>> {
    let payload_b64 = jwt.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let exp = claims.get("exp").and_then(serde_json::Value::as_i64)?;
    Utc.timestamp_opt(exp, 0).single()
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn source_mapping_covers_known_providers() {
        assert_eq!(source_for("openai-codex"), Some(SystemSource::Codex));
        assert_eq!(
            source_for("anthropic-max"),
            Some(SystemSource::ClaudeKeychain)
        );
        assert_eq!(source_for("claude-max"), Some(SystemSource::ClaudeKeychain));
        assert_eq!(source_for("gemini"), None);
    }

    #[test]
    fn grob_refreshes_codex_but_not_claude() {
        // Codex token is grob-private once adopted — safe to refresh.
        assert!(grob_may_refresh("openai-codex"));
        // Claude keychain is shared by every Claude Code session — read-only.
        assert!(!grob_may_refresh("anthropic-max"));
        assert!(!grob_may_refresh("claude-max"));
    }

    #[test]
    fn parses_codex_payload_with_jwt_expiry() {
        // exp = 4102444800 (2100-01-01T00:00:00Z), encoded as a JWT payload.
        let payload = URL_SAFE_NO_PAD.encode(br#"{"exp":4102444800}"#);
        let jwt = format!("header.{payload}.sig");
        let raw = format!(r#"{{"tokens":{{"access_token":"{jwt}","refresh_token":"rt-codex"}}}}"#);
        let token = parse_codex_payload("openai-codex", &raw).unwrap();
        assert_eq!(token.provider_id, "openai-codex");
        assert_eq!(token.refresh_token.expose_secret(), "rt-codex");
        assert_eq!(token.expires_at.timestamp(), 4102444800);
    }

    #[test]
    fn parses_claude_keychain_payload() {
        let raw = r#"{"claudeAiOauth":{"accessToken":"at-claude","refreshToken":"rt-claude","expiresAt":4102444800000,"scopes":["user:inference"]}}"#;
        let token = parse_claude_payload("anthropic-max", raw).unwrap();
        assert_eq!(token.provider_id, "anthropic-max");
        assert_eq!(token.access_token.expose_secret(), "at-claude");
        assert_eq!(token.refresh_token.expose_secret(), "rt-claude");
        // 4102444800000 ms == 4102444800 s == 2100-01-01T00:00:00Z.
        assert_eq!(token.expires_at.timestamp(), 4102444800);
    }

    #[test]
    fn rejects_payload_missing_tokens() {
        assert!(parse_codex_payload("openai-codex", r#"{"auth_mode":"chatgpt"}"#).is_err());
        assert!(parse_claude_payload("anthropic-max", r#"{"other":1}"#).is_err());
    }
}

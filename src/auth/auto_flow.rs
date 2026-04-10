//! Automatic credential setup at startup.
//!
//! Detects missing OAuth tokens and API keys, then interactively
//! walks the user through setup. Providers that are already configured
//! are silently skipped.

use anyhow::Result;
use secrecy::ExposeSecret;
use std::io::{self, BufRead, Write};

use crate::auth::oauth::{OAuthClient, OAuthConfig};
use crate::auth::token_store::TokenStore;
use crate::providers::{AuthType, ProviderConfig};

/// Status of a single provider's credentials.
pub enum CredentialStatus {
    /// Provider is fully configured and ready.
    Ready,
    /// OAuth token is missing for this provider.
    MissingOAuth {
        /// Human-readable provider name from config.
        provider_name: String,
        /// Token store key (e.g. "anthropic-max", "openai-codex").
        oauth_provider_id: String,
        /// OAuth type string for [`OAuthConfig`] lookup.
        oauth_type: String,
    },
    /// API key environment variable is not set.
    MissingApiKey {
        /// Human-readable provider name from config.
        provider_name: String,
        /// Environment variable name that should hold the key.
        env_var: String,
    },
}

/// Mapping from oauth_provider_id to the oauth_type string used by OAuthConfig.
fn oauth_type_for_provider_id(oauth_provider_id: &str) -> Option<&'static str> {
    match oauth_provider_id {
        "anthropic-max" => Some("max"),
        "openai-codex" => Some("openai-codex"),
        "gemini" => Some("gemini"),
        _ => None,
    }
}

/// Build an OAuthConfig for a given oauth_type string.
fn oauth_config_for_type(oauth_type: &str) -> Option<OAuthConfig> {
    match oauth_type {
        "max" => Some(OAuthConfig::anthropic()),
        "openai-codex" => Some(OAuthConfig::openai_codex()),
        "gemini" => Some(OAuthConfig::gemini()),
        _ => None,
    }
}

/// Checks all providers and returns their credential status.
pub fn detect_credentials(
    providers: &[ProviderConfig],
    token_store: &TokenStore,
) -> Vec<CredentialStatus> {
    let mut statuses = Vec::new();

    for provider in providers {
        if provider.enabled == Some(false) {
            continue;
        }

        match provider.auth_type {
            AuthType::OAuth => {
                if let Some(ref oauth_id) = provider.oauth_provider {
                    let token = token_store.get(oauth_id);
                    let has_valid_token = token.as_ref().is_some_and(|t| !t.is_expired());
                    if has_valid_token {
                        statuses.push(CredentialStatus::Ready);
                    } else {
                        let oauth_type = oauth_type_for_provider_id(oauth_id)
                            .unwrap_or("max")
                            .to_string();
                        statuses.push(CredentialStatus::MissingOAuth {
                            provider_name: provider.name.clone(),
                            oauth_provider_id: oauth_id.clone(),
                            oauth_type,
                        });
                    }
                }
            }
            AuthType::ApiKey => {
                if let Some(ref key) = provider.api_key {
                    let key_str = key.expose_secret();
                    if let Some(var) = key_str.strip_prefix('$') {
                        if std::env::var(var).is_ok() {
                            statuses.push(CredentialStatus::Ready);
                        } else {
                            statuses.push(CredentialStatus::MissingApiKey {
                                provider_name: provider.name.clone(),
                                env_var: var.to_string(),
                            });
                        }
                    } else {
                        // Inline key, always ready.
                        statuses.push(CredentialStatus::Ready);
                    }
                }
            }
        }
    }

    statuses
}

/// Runs the interactive credential setup flow.
///
/// Returns the number of providers that were successfully configured.
/// Providers the user skips are left unconfigured (they will be
/// disabled at runtime).
pub async fn run_interactive_flow(
    statuses: Vec<CredentialStatus>,
    token_store: &TokenStore,
) -> Result<usize> {
    let missing: Vec<_> = statuses
        .into_iter()
        .filter(|s| !matches!(s, CredentialStatus::Ready))
        .collect();

    if missing.is_empty() {
        return Ok(0);
    }

    let total = missing.len();
    eprintln!();
    eprintln!("  Missing credentials ({}):", total);
    for status in &missing {
        match status {
            CredentialStatus::MissingOAuth { provider_name, .. } => {
                eprintln!("    ⚠️  {} — OAuth token missing", provider_name);
            }
            CredentialStatus::MissingApiKey {
                provider_name,
                env_var,
            } => {
                eprintln!("    ⚠️  {} — ${} not set", provider_name, env_var);
            }
            CredentialStatus::Ready => {}
        }
    }
    eprintln!();

    let mut configured = 0;
    let stdin = io::stdin();

    for status in missing {
        match status {
            CredentialStatus::MissingOAuth {
                provider_name,
                oauth_provider_id,
                oauth_type,
            } => {
                if setup_oauth_interactive(
                    &provider_name,
                    &oauth_provider_id,
                    &oauth_type,
                    token_store,
                    &stdin,
                )
                .await?
                {
                    configured += 1;
                }
            }
            CredentialStatus::MissingApiKey {
                provider_name,
                env_var,
            } => {
                if setup_api_key_interactive(&provider_name, &env_var, &stdin).await? {
                    configured += 1;
                }
            }
            CredentialStatus::Ready => {}
        }
    }

    if configured > 0 {
        eprintln!("  ✅ Configured {}/{} providers", configured, total);
    }
    eprintln!();

    Ok(configured)
}

/// Interactive OAuth setup: print URL, wait for code, exchange.
async fn setup_oauth_interactive(
    provider_name: &str,
    oauth_provider_id: &str,
    oauth_type: &str,
    token_store: &TokenStore,
    stdin: &io::Stdin,
) -> Result<bool> {
    eprintln!("  {} (OAuth):", provider_name);
    eprintln!("    [1] Authenticate now");
    eprintln!("    [2] Skip (provider disabled until configured)");
    eprint!("    > ");
    io::stderr().flush()?;

    let mut input = String::new();
    stdin.lock().read_line(&mut input)?;
    let choice = input.trim();

    if choice != "1" {
        eprintln!("    Skipped — run `grob connect` later");
        eprintln!();
        return Ok(false);
    }

    let config = match oauth_config_for_type(oauth_type) {
        Some(c) => c,
        None => {
            eprintln!("    ❌ Unsupported OAuth type configured");
            return Ok(false);
        }
    };

    let client = OAuthClient::new(config, token_store.clone());
    let auth_url = client.authorization_url()?;

    eprintln!();
    eprintln!("    Open this URL in your browser:");
    eprintln!();
    eprintln!("    {}", auth_url.url);
    eprintln!();
    eprintln!("    After authorizing, paste the code below.");
    eprint!("    Code: ");
    io::stderr().flush()?;

    let mut code = String::new();
    stdin.lock().read_line(&mut code)?;
    let code = code.trim();

    if code.is_empty() {
        eprintln!("    ❌ No code entered, skipping");
        return Ok(false);
    }

    match client
        .exchange_code(code, auth_url.verifier.verifier(), oauth_provider_id)
        .await
    {
        Ok(mut token) => {
            // For Gemini, try to get project ID.
            if oauth_type == "gemini" {
                match client
                    .load_code_assist(token.access_token.expose_secret())
                    .await
                {
                    Ok(project_id) => {
                        token.project_id = Some(project_id);
                        token_store.save(token)?;
                    }
                    Err(_) => {
                        // Optional for individual accounts.
                    }
                }
            }
            eprintln!("    ✅ {} authenticated", provider_name);
            eprintln!();
            Ok(true)
        }
        Err(e) => {
            eprintln!("    ❌ Authentication failed: {}", e);
            eprintln!("    Run `grob connect` to try again");
            eprintln!();
            Ok(false)
        }
    }
}

/// Interactive API key setup: prompt for key or skip.
async fn setup_api_key_interactive(
    provider_name: &str,
    env_var: &str,
    stdin: &io::Stdin,
) -> Result<bool> {
    eprintln!("  {} (${})", provider_name, env_var);
    eprintln!("    [1] Enter API key now");
    eprintln!("    [2] Skip (provider disabled until configured)");
    eprint!("    > ");
    io::stderr().flush()?;

    let mut input = String::new();
    stdin.lock().read_line(&mut input)?;
    let choice = input.trim();

    if choice != "1" {
        eprintln!("    Skipped — set ${} and restart", env_var);
        eprintln!();
        return Ok(false);
    }

    eprint!("    API key: ");
    io::stderr().flush()?;

    let mut key = String::new();
    stdin.lock().read_line(&mut key)?;
    let key = key.trim();

    if key.is_empty() {
        eprintln!("    ❌ No key entered, skipping");
        return Ok(false);
    }

    // Best-effort validation before accepting.
    let valid = crate::commands::credential_check::validate_api_key(provider_name, key).await;
    if !valid {
        eprintln!(
            "    ⚠️  Token may be invalid ({} returned auth error). Continue anyway? [y/N]",
            provider_name
        );
        eprint!("    > ");
        io::stderr().flush()?;
        let mut answer = String::new();
        stdin.lock().read_line(&mut answer)?;
        if !answer.trim().eq_ignore_ascii_case("y") && !answer.trim().eq_ignore_ascii_case("yes") {
            eprintln!("    Key rejected by user");
            return Ok(false);
        }
    }

    // Keep the $ENV_VAR reference in config.toml — never store raw keys on disk.
    // Instead, instruct the user to export the key in their shell profile.
    eprintln!(
        "    ✅ Key accepted (stored as ${} reference in config)",
        env_var
    );
    eprintln!();
    eprintln!("    Add to your shell profile:");
    eprintln!("      export {}={}", env_var, key);
    eprintln!();
    Ok(true)
}

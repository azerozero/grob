use crate::providers::AuthType;
use crate::{cli, preset};

/// Launches interactive credential setup for one or all providers.
///
/// When `force_reauth` is set, any existing OAuth tokens for the targeted
/// provider(s) are deleted and a fresh PKCE flow is initiated.
///
/// The provider argument matches against either `[[providers]] name` or
/// `[[providers]] oauth_provider`, so `grob connect anthropic-max` and
/// `grob connect anthropic` both reach the Anthropic OAuth flow when the
/// config wires them together (a frequent source of confusion in support
/// threads).
pub async fn cmd_connect(
    config: &cli::AppConfig,
    config_source: &cli::ConfigSource,
    provider: Option<String>,
    force_reauth: bool,
) -> anyhow::Result<()> {
    let file_path = match config_source {
        cli::ConfigSource::File(p) => p.clone(),
        cli::ConfigSource::Url(_) => {
            eprintln!("❌ Cannot manage credentials for a remote URL config");
            return Ok(());
        }
    };

    // Resolve the user-supplied identifier (which may be either the
    // provider name or the oauth_provider id) to the canonical provider
    // name used everywhere else in the codebase.
    let resolved_provider: Option<String> = if let Some(ref id) = provider {
        if let Some(p) = config
            .providers
            .iter()
            .find(|p| p.name == *id || p.oauth_provider.as_deref() == Some(id.as_str()))
        {
            if p.name != *id {
                println!(
                    "ℹ  '{}' resolves to provider '{}' (oauth_provider={}). Using canonical name.",
                    id,
                    p.name,
                    p.oauth_provider.as_deref().unwrap_or("?")
                );
            }
            Some(p.name.clone())
        } else {
            eprintln!("❌ Provider '{}' not found in config", id);
            eprintln!(
                "   Available names:           {}",
                config
                    .providers
                    .iter()
                    .map(|p| p.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            let oauth_ids: Vec<&str> = config
                .providers
                .iter()
                .filter_map(|p| p.oauth_provider.as_deref())
                .collect();
            if !oauth_ids.is_empty() {
                eprintln!("   Available oauth_provider:  {}", oauth_ids.join(", "));
            }
            return Ok(());
        }
    } else {
        None
    };

    if force_reauth {
        return force_reauth_flow(config, resolved_provider.as_deref()).await;
    }

    // OAuth fast path: when the targeted provider uses OAuth and has no
    // stored token, drive the browser flow directly here. This avoids the
    // legacy "OAuth will be set up on first `grob start`" message which
    // misled users into chaining `grob connect` then `grob start` then
    // hitting the "already running" error.
    if let Some(ref provider_name) = resolved_provider {
        let target = config
            .providers
            .iter()
            .find(|p| p.name == *provider_name)
            .expect("resolved provider exists by construction");

        if target.auth_type == AuthType::OAuth {
            return run_oauth_flow_for_provider(config, provider_name).await;
        }
    }

    if let Some(ref provider_name) = resolved_provider {
        println!("🔑 Setting up credentials for '{}'...", provider_name);
        if let Err(e) =
            preset::setup_credentials_interactive_filtered(&file_path, Some(provider_name))
        {
            eprintln!("❌ Credential setup failed: {}", e);
        }
    } else {
        println!("🔑 Setting up credentials for all providers...");
        if let Err(e) = preset::setup_credentials_interactive(&file_path) {
            eprintln!("❌ Credential setup failed: {}", e);
        }
    }
    Ok(())
}

/// Runs the PKCE browser flow for a single OAuth provider (no token
/// deletion, unlike `force_reauth_flow`). If a valid token already exists,
/// reports that and exits without prompting again.
async fn run_oauth_flow_for_provider(
    config: &cli::AppConfig,
    provider_name: &str,
) -> anyhow::Result<()> {
    use crate::auth::auto_flow::{detect_credentials, run_interactive_flow, CredentialStatus};
    use crate::auth::TokenStore;
    use crate::storage::GrobStore;
    use std::sync::Arc;

    let grob_store = Arc::new(
        GrobStore::open(&GrobStore::default_path())
            .map_err(|e| anyhow::anyhow!("Failed to initialize credential storage: {}", e))?,
    );

    #[cfg(feature = "oauth")]
    let token_store = TokenStore::with_store(grob_store.clone())
        .map_err(|e| anyhow::anyhow!("Failed to initialize token store: {}", e))?;
    #[cfg(not(feature = "oauth"))]
    let token_store = {
        let _ = &grob_store;
        TokenStore::new_empty()
    };

    let statuses = detect_credentials(&config.providers, &token_store);
    let needs_oauth: Vec<CredentialStatus> = statuses
        .into_iter()
        .filter(|s| {
            matches!(s, CredentialStatus::MissingOAuth { provider_name: name, .. } if name == provider_name)
        })
        .collect();

    if needs_oauth.is_empty() {
        println!(
            "✅ Provider '{}' already has a valid OAuth token.",
            provider_name
        );
        println!(
            "   Use `grob connect {} --force-reauth` to redo.",
            provider_name
        );
        return Ok(());
    }

    println!("🔑 Launching OAuth flow for '{}'...", provider_name);
    println!("   A browser window will open. Sign in to grant access.");
    run_interactive_flow(needs_oauth, &token_store).await?;
    println!("✅ OAuth setup complete. You can now run `grob start` or `grob exec -- <cmd>`.");
    Ok(())
}

/// Deletes existing OAuth tokens for `provider` (all OAuth providers if
/// `None`), then triggers a fresh interactive OAuth flow.
async fn force_reauth_flow(config: &cli::AppConfig, provider: Option<&str>) -> anyhow::Result<()> {
    use crate::auth::auto_flow::{detect_credentials, run_interactive_flow, CredentialStatus};
    use crate::auth::TokenStore;
    use crate::providers::AuthType;
    use crate::storage::GrobStore;
    use std::sync::Arc;

    println!("🔁 Force re-authentication flow");

    let grob_store = Arc::new(
        GrobStore::open(&GrobStore::default_path())
            .map_err(|e| anyhow::anyhow!("Failed to initialize credential storage: {}", e))?,
    );

    #[cfg(feature = "oauth")]
    let token_store = TokenStore::with_store(grob_store.clone())
        .map_err(|e| anyhow::anyhow!("Failed to initialize token store: {}", e))?;
    #[cfg(not(feature = "oauth"))]
    let token_store = {
        let _ = &grob_store;
        TokenStore::new_empty()
    };

    // Step 1: Drop existing tokens for targeted OAuth providers.
    let mut removed = 0usize;
    for p in &config.providers {
        if p.enabled == Some(false) {
            continue;
        }
        if p.auth_type != AuthType::OAuth {
            continue;
        }
        if let Some(filter) = provider {
            if p.name != filter {
                continue;
            }
        }
        if let Some(ref oauth_id) = p.oauth_provider {
            if token_store.get(oauth_id).is_some() {
                match token_store.remove(oauth_id) {
                    Ok(_) => {
                        println!("  🗑  Deleted OAuth token for {} ({})", p.name, oauth_id);
                        removed += 1;
                    }
                    Err(e) => {
                        eprintln!("  ⚠  Failed to delete token for {}: {}", p.name, e);
                    }
                }
            }
        }
    }

    if removed == 0 {
        println!("  (no existing OAuth tokens found for the requested scope)");
    }

    // Step 2: Re-detect and run the interactive flow, which will now find the
    // token missing and walk the user through the PKCE flow from scratch.
    let statuses = detect_credentials(&config.providers, &token_store);
    let filtered: Vec<CredentialStatus> = if let Some(filter) = provider {
        statuses
            .into_iter()
            .filter(|s| match s {
                CredentialStatus::MissingOAuth { provider_name, .. }
                | CredentialStatus::MissingApiKey { provider_name, .. } => provider_name == filter,
                CredentialStatus::Ready => false,
            })
            .collect()
    } else {
        statuses
    };

    if filtered.is_empty() {
        println!("  Nothing to re-authenticate (no OAuth providers configured).");
        return Ok(());
    }

    run_interactive_flow(filtered, &token_store).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::auth::token_store::{OAuthToken, TokenStore};
    use chrono::Utc;
    use secrecy::SecretString;
    use tempfile::TempDir;

    fn make_token(provider_id: &str) -> OAuthToken {
        OAuthToken {
            provider_id: provider_id.to_string(),
            access_token: SecretString::new("access".into()),
            refresh_token: SecretString::new("refresh".into()),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            enterprise_url: None,
            project_id: None,
            needs_reauth: None,
        }
    }

    #[test]
    fn force_reauth_removes_existing_token() {
        // Simulates the token-deletion half of the force-reauth flow without
        // invoking the interactive OAuth handshake (which requires a browser).
        let dir = TempDir::new().unwrap();
        let store = TokenStore::new(dir.path().join("tokens.json")).unwrap();
        store.save(make_token("anthropic-max")).unwrap();
        assert!(store.get("anthropic-max").is_some());

        store.remove("anthropic-max").unwrap();

        assert!(store.get("anthropic-max").is_none());
    }

    #[test]
    fn force_reauth_filters_to_single_provider() {
        // A --force-reauth targeted at one provider must not touch others.
        let dir = TempDir::new().unwrap();
        let store = TokenStore::new(dir.path().join("tokens.json")).unwrap();
        store.save(make_token("anthropic-max")).unwrap();
        store.save(make_token("openai-codex")).unwrap();

        // Remove only the filtered provider.
        store.remove("anthropic-max").unwrap();

        assert!(store.get("anthropic-max").is_none());
        assert!(store.get("openai-codex").is_some());
    }

    #[test]
    fn force_reauth_is_idempotent_when_no_token() {
        let dir = TempDir::new().unwrap();
        let store = TokenStore::new(dir.path().join("tokens.json")).unwrap();
        // No token stored — removing a non-existent token must not error.
        store.remove("anthropic-max").unwrap();
        assert!(store.get("anthropic-max").is_none());
    }
}

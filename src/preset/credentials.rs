//! Credential checking and interactive setup wizard.

use anyhow::{Context, Result};
use std::path::Path;

/// What kind of auth a provider needs
#[derive(Debug)]
enum ProviderAuth {
    /// Needs an API key via env var (e.g. $OPENROUTER_API_KEY)
    EnvApiKey { env_var: String },
    /// Uses OAuth — check token store
    OAuth { oauth_provider: String },
    /// Already has a literal API key in config
    Configured,
}

/// Status of a provider's credentials
#[derive(Debug)]
pub struct CredentialStatus {
    pub provider_name: String,
    pub provider_type: String,
    pub ok: bool,
    pub detail: String,
}

/// Check credentials for all providers in the config and return status.
pub fn check_credentials(config_path: &Path) -> Result<Vec<CredentialStatus>> {
    let content = std::fs::read_to_string(config_path)
        .with_context(|| format!("Failed to read config: {}", config_path.display()))?;

    let config: toml::Value = toml::from_str(&content)
        .with_context(|| format!("Failed to parse config: {}", config_path.display()))?;

    let providers = config
        .get("providers")
        .and_then(|p| p.as_array())
        .map(|a| a.to_vec())
        .unwrap_or_default();

    // Load OAuth token store to check for existing tokens
    let oauth_providers = load_oauth_provider_list();

    let mut statuses = Vec::new();

    for provider in &providers {
        let name = provider
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("?")
            .to_string();
        let ptype = provider
            .get("provider_type")
            .and_then(|t| t.as_str())
            .unwrap_or("?")
            .to_string();
        let enabled = provider
            .get("enabled")
            .and_then(|e| e.as_bool())
            .unwrap_or(true);

        if !enabled {
            statuses.push(CredentialStatus {
                provider_name: name,
                provider_type: ptype,
                ok: true,
                detail: "disabled".to_string(),
            });
            continue;
        }

        let auth = detect_auth_type(provider);

        let status = match auth {
            ProviderAuth::Configured => CredentialStatus {
                provider_name: name,
                provider_type: ptype,
                ok: true,
                detail: "API key configured".to_string(),
            },
            ProviderAuth::OAuth { ref oauth_provider } => {
                if oauth_providers.contains(oauth_provider) {
                    CredentialStatus {
                        provider_name: name,
                        provider_type: ptype,
                        ok: true,
                        detail: format!("OAuth token found ({})", oauth_provider),
                    }
                } else {
                    CredentialStatus {
                        provider_name: name,
                        provider_type: ptype,
                        ok: false,
                        detail: format!(
                            "No OAuth token for '{}' — run grob start, it will prompt OAuth login",
                            oauth_provider
                        ),
                    }
                }
            }
            ProviderAuth::EnvApiKey { ref env_var } => {
                if std::env::var(env_var).is_ok() {
                    CredentialStatus {
                        provider_name: name,
                        provider_type: ptype,
                        ok: true,
                        detail: format!("{} set", env_var),
                    }
                } else {
                    CredentialStatus {
                        provider_name: name,
                        provider_type: ptype,
                        ok: false,
                        detail: format!("{} not set", env_var),
                    }
                }
            }
        };

        statuses.push(status);
    }

    Ok(statuses)
}

/// Detect what auth a provider entry needs.
fn detect_auth_type(provider: &toml::Value) -> ProviderAuth {
    let auth_type = provider
        .get("auth_type")
        .and_then(|a| a.as_str())
        .unwrap_or("api_key");

    if auth_type == "oauth" {
        let oauth_provider = provider
            .get("oauth_provider")
            .and_then(|o| o.as_str())
            .unwrap_or("")
            .to_string();
        return ProviderAuth::OAuth { oauth_provider };
    }

    // API key auth
    let api_key = provider
        .get("api_key")
        .and_then(|k| k.as_str())
        .unwrap_or("");

    if let Some(var_name) = api_key.strip_prefix('$') {
        // Environment variable reference
        ProviderAuth::EnvApiKey {
            env_var: var_name.to_string(),
        }
    } else if !api_key.is_empty() {
        ProviderAuth::Configured
    } else {
        // No key at all — infer env var name from provider name
        let provider_name = provider
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("UNKNOWN")
            .to_uppercase()
            .replace('-', "_");
        ProviderAuth::EnvApiKey {
            env_var: format!("{}_API_KEY", provider_name),
        }
    }
}

/// Public accessor for OAuth provider list (used by status command)
pub fn load_oauth_provider_list_pub() -> Vec<String> {
    load_oauth_provider_list()
}

/// Load the list of OAuth provider IDs that have tokens stored.
fn load_oauth_provider_list() -> Vec<String> {
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return vec![],
    };
    let tokens_path = home.join(".grob").join("oauth_tokens.json");
    if !tokens_path.exists() {
        return vec![];
    }
    let content = match std::fs::read_to_string(&tokens_path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };
    // oauth_tokens.json is { "provider-id": { ... }, ... }
    let parsed: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return vec![],
    };
    parsed
        .as_object()
        .map(|obj| obj.keys().cloned().collect())
        .unwrap_or_default()
}

/// Interactive credential setup wizard.
/// For each provider missing credentials, prompts the user to enter an API key
/// or skip. Writes entered keys directly into the config file.
pub fn setup_credentials_interactive(config_path: &Path) -> Result<()> {
    setup_credentials_interactive_filtered(config_path, None)
}

/// Prompt the user for a single missing credential. Returns true if config was modified.
fn prompt_for_credential(status: &CredentialStatus, config: &mut toml::Value) -> Result<bool> {
    if status.detail.contains("OAuth") {
        println!(
            "  {} — OAuth will be set up on first `grob start`",
            status.provider_name
        );
        return Ok(false);
    }

    println!("  {} ({}):", status.provider_name, status.provider_type);
    println!("    [1] Enter API key now");
    println!("    [2] I'll set the env var later");
    println!("    [3] Skip (disable this provider)");
    print!("    > ");

    use std::io::Write;
    std::io::stdout().flush()?;

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let choice = input.trim();

    let changed = match choice {
        "1" => {
            print!("    API key: ");
            std::io::stdout().flush()?;
            let mut key = String::new();
            std::io::stdin().read_line(&mut key)?;
            let key = key.trim().to_string();

            if key.is_empty() {
                println!("    Skipped (empty input)");
                false
            } else {
                if let Some(providers) = config.get_mut("providers").and_then(|p| p.as_array_mut())
                {
                    for provider in providers.iter_mut() {
                        let pname = provider.get("name").and_then(|n| n.as_str()).unwrap_or("");
                        if pname == status.provider_name {
                            if let Some(ptable) = provider.as_table_mut() {
                                ptable.insert(
                                    "api_key".to_string(),
                                    toml::Value::String(key.clone()),
                                );
                            }
                        }
                    }
                }
                println!("    ✅ Saved to config");
                true
            }
        }
        "3" => {
            if let Some(providers) = config.get_mut("providers").and_then(|p| p.as_array_mut()) {
                for provider in providers.iter_mut() {
                    let pname = provider.get("name").and_then(|n| n.as_str()).unwrap_or("");
                    if pname == status.provider_name {
                        if let Some(ptable) = provider.as_table_mut() {
                            ptable.insert("enabled".to_string(), toml::Value::Boolean(false));
                        }
                    }
                }
            }
            println!("    Provider disabled");
            true
        }
        _ => {
            println!(
                "    OK — set {} before running grob",
                status
                    .detail
                    .split_whitespace()
                    .next()
                    .unwrap_or("the env var")
            );
            false
        }
    };
    println!();
    Ok(changed)
}

/// Interactive credential setup wizard with optional provider filter.
pub fn setup_credentials_interactive_filtered(
    config_path: &Path,
    filter_provider: Option<&str>,
) -> Result<()> {
    let statuses = check_credentials(config_path)?;

    println!();
    println!("📋 Checking credentials...");
    println!();

    let mut all_ok = true;
    let mut missing: Vec<&CredentialStatus> = Vec::new();

    for s in &statuses {
        // Skip providers not matching filter
        if let Some(filter) = filter_provider {
            if s.provider_name != filter {
                continue;
            }
        }

        if s.ok {
            println!(
                "  {} ({}): ✅ {}",
                s.provider_name, s.provider_type, s.detail
            );
        } else {
            println!(
                "  {} ({}): ⚠️  {}",
                s.provider_name, s.provider_type, s.detail
            );
            all_ok = false;
            missing.push(s);
        }
    }

    if all_ok {
        println!();
        println!("  All credentials OK!");
        return Ok(());
    }

    println!();

    // Read config for modification
    let content = std::fs::read_to_string(config_path)?;
    let mut config: toml::Value = toml::from_str(&content)?;

    let mut config_changed = false;

    for status in &missing {
        if prompt_for_credential(status, &mut config)? {
            config_changed = true;
        }
    }

    if config_changed {
        let output = toml::to_string_pretty(&config)?;
        std::fs::write(config_path, &output)?;
    }

    Ok(())
}

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

const BUILTIN_PERF: &str = include_str!("../presets/perf.toml");
const BUILTIN_MEDIUM: &str = include_str!("../presets/medium.toml");
const BUILTIN_LOCAL: &str = include_str!("../presets/local.toml");
const BUILTIN_CHEAP: &str = include_str!("../presets/cheap.toml");
const BUILTIN_FAST: &str = include_str!("../presets/fast.toml");
const BUILTIN_GDPR: &str = include_str!("../presets/gdpr.toml");
const BUILTIN_EU_AI_ACT: &str = include_str!("../presets/eu-ai-act.toml");

#[derive(Debug)]
pub struct PresetInfo {
    pub name: String,
    pub description: String,
    pub is_builtin: bool,
}

/// Get the presets directory: ~/.grob/presets/
pub fn preset_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().context("Failed to get home directory")?;
    let dir = home.join(".grob").join("presets");
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("Failed to create presets directory: {}", dir.display()))?;
    Ok(dir)
}

/// List all available presets (builtins + installed)
pub fn list_presets() -> Result<Vec<PresetInfo>> {
    let mut presets = vec![
        PresetInfo {
            name: "perf".to_string(),
            description: "Performance max — Anthropic + OpenAI + Gemini, top models".to_string(),
            is_builtin: true,
        },
        PresetInfo {
            name: "medium".to_string(),
            description: "Best quality/price — Anthropic thinking + OpenRouter defaults"
                .to_string(),
            is_builtin: true,
        },
        PresetInfo {
            name: "local".to_string(),
            description: "Ollama local + Anthropic thinking — private, zero API cost for defaults"
                .to_string(),
            is_builtin: true,
        },
        PresetInfo {
            name: "cheap".to_string(),
            description: "Budget max — GLM-5 + DeepSeek + Gemini Flash, $0-5/month".to_string(),
            is_builtin: true,
        },
        PresetInfo {
            name: "fast".to_string(),
            description: "Premium rapide — Opus + GPT-5.2 + Gemini Pro, qualite max sans limite"
                .to_string(),
            is_builtin: true,
        },
        PresetInfo {
            name: "gdpr".to_string(),
            description: "EU-only GDPR compliant — Mistral, Scaleway, OVH (region=eu)".to_string(),
            is_builtin: true,
        },
        PresetInfo {
            name: "eu-ai-act".to_string(),
            description:
                "EU AI Act compliant — EU providers + transparency headers + risk classification"
                    .to_string(),
            is_builtin: true,
        },
    ];

    // Scan installed presets directory
    let dir = preset_dir()?;
    if dir.exists() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("toml") {
                let name = path
                    .file_stem()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown")
                    .to_string();

                // Skip if it shadows a builtin
                if presets.iter().any(|p| p.name == name) {
                    continue;
                }

                presets.push(PresetInfo {
                    name,
                    description: "Installed preset".to_string(),
                    is_builtin: false,
                });
            }
        }
    }

    Ok(presets)
}

/// Get preset content by name (builtin or installed file)
pub fn get_preset_content(name: &str) -> Result<String> {
    // Check builtins first
    match name {
        "perf" => return Ok(BUILTIN_PERF.to_string()),
        "medium" => return Ok(BUILTIN_MEDIUM.to_string()),
        "local" => return Ok(BUILTIN_LOCAL.to_string()),
        "cheap" => return Ok(BUILTIN_CHEAP.to_string()),
        "fast" => return Ok(BUILTIN_FAST.to_string()),
        "gdpr" => return Ok(BUILTIN_GDPR.to_string()),
        "eu-ai-act" => return Ok(BUILTIN_EU_AI_ACT.to_string()),
        _ => {}
    }

    // Check installed presets
    let dir = preset_dir()?;
    let path = dir.join(format!("{}.toml", name));
    if path.exists() {
        return std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read preset: {}", path.display()));
    }

    anyhow::bail!(
        "Preset '{}' not found. Use 'grob preset list' to see available presets.",
        name
    );
}

/// Print detailed info about a preset (providers, models, env vars, routing).
pub fn print_preset_info(name: &str) -> Result<()> {
    let content = get_preset_content(name)?;
    let preset: toml::Value =
        toml::from_str(&content).with_context(|| format!("Failed to parse preset '{}'", name))?;

    // Find description from list
    let presets = list_presets()?;
    let desc = presets
        .iter()
        .find(|p| p.name == name)
        .map(|p| p.description.as_str())
        .unwrap_or("Custom preset");
    let tag = presets
        .iter()
        .find(|p| p.name == name)
        .map(|p| if p.is_builtin { "builtin" } else { "installed" })
        .unwrap_or("?");

    println!("📦 Preset: {} [{}]", name, tag);
    println!("   {}", desc);

    // Providers
    if let Some(providers) = preset.get("providers").and_then(|p| p.as_array()) {
        println!();
        println!("📡 Providers ({}):", providers.len());
        for p in providers {
            let pname = p.get("name").and_then(|n| n.as_str()).unwrap_or("?");
            let ptype = p
                .get("provider_type")
                .and_then(|t| t.as_str())
                .unwrap_or("?");
            let auth = p
                .get("auth_type")
                .and_then(|a| a.as_str())
                .unwrap_or("api_key");
            let enabled = p.get("enabled").and_then(|e| e.as_bool()).unwrap_or(true);
            let base_url = p.get("base_url").and_then(|u| u.as_str());

            let status = if enabled { "" } else { " (disabled)" };

            let auth_info = if auth == "oauth" {
                let oauth_id = p
                    .get("oauth_provider")
                    .and_then(|o| o.as_str())
                    .unwrap_or("?");
                format!("OAuth ({})", oauth_id)
            } else {
                let key = p.get("api_key").and_then(|k| k.as_str()).unwrap_or("");
                if key.starts_with('$') {
                    format!("env: {}", key)
                } else if !key.is_empty() {
                    "API key (set)".to_string()
                } else {
                    "no key".to_string()
                }
            };

            println!("   {} ({}) — {}{}", pname, ptype, auth_info, status);
            if let Some(url) = base_url {
                println!("     URL: {}", url);
            }
        }
    }

    // Router
    if let Some(router) = preset.get("router").and_then(|r| r.as_table()) {
        println!();
        println!("🔀 Router:");
        let roles = [
            ("default", "Default"),
            ("think", "Think"),
            ("background", "Background"),
            ("websearch", "WebSearch"),
        ];
        for (key, label) in &roles {
            if let Some(v) = router.get(*key).and_then(|v| v.as_str()) {
                println!("   {:<12} → {}", label, v);
            }
        }
    }

    // Models with mappings
    if let Some(models) = preset.get("models").and_then(|m| m.as_array()) {
        println!();
        println!("🧩 Models ({}):", models.len());
        for model in models {
            let mname = model.get("name").and_then(|n| n.as_str()).unwrap_or("?");
            let mappings = model.get("mappings").and_then(|m| m.as_array());

            println!("   {}:", mname);
            if let Some(mappings) = mappings {
                for m in mappings {
                    let prio = m.get("priority").and_then(|p| p.as_integer()).unwrap_or(0);
                    let provider = m.get("provider").and_then(|p| p.as_str()).unwrap_or("?");
                    let actual = m
                        .get("actual_model")
                        .and_then(|a| a.as_str())
                        .unwrap_or("?");
                    println!("     [{}] {}/{}", prio, provider, actual);
                }
            }
        }
    }

    // Required env vars
    let mut env_vars: Vec<String> = Vec::new();
    let mut needs_oauth = false;
    let mut needs_ollama = false;

    if let Some(providers) = preset.get("providers").and_then(|p| p.as_array()) {
        for p in providers {
            let enabled = p.get("enabled").and_then(|e| e.as_bool()).unwrap_or(true);
            if !enabled {
                continue;
            }

            let auth = p
                .get("auth_type")
                .and_then(|a| a.as_str())
                .unwrap_or("api_key");
            if auth == "oauth" {
                needs_oauth = true;
            }

            let base_url = p.get("base_url").and_then(|u| u.as_str()).unwrap_or("");
            if base_url.contains("localhost") || base_url.contains("127.0.0.1") {
                needs_ollama = true;
            }

            if let Some(key) = p.get("api_key").and_then(|k| k.as_str()) {
                if let Some(var_name) = key.strip_prefix('$') {
                    let var = var_name.to_string();
                    if !env_vars.contains(&var) {
                        env_vars.push(var);
                    }
                }
            }
        }
    }

    println!();
    println!("📋 Requirements:");
    if needs_oauth {
        println!("   - Anthropic OAuth (Max plan) — auto-prompted on first grob start");
    }
    if needs_ollama {
        println!("   - Ollama running at http://localhost:11434");
        println!("     Install: curl -fsSL https://ollama.ai/install.sh | sh");
        println!("     Models: ollama pull qwen2.5-coder:32b && ollama pull qwen2.5-coder:7b");
    }
    for var in &env_vars {
        let set = std::env::var(var).is_ok();
        let icon = if set { "✅" } else { "⚠️" };
        println!(
            "   {} {} {}",
            icon,
            var,
            if set { "(set)" } else { "(not set)" }
        );
    }

    Ok(())
}

/// Apply a preset to the config file.
/// Keeps [server] and [presets] sections, replaces [router] + [[providers]] + [[models]].
pub fn apply_preset(name: &str, config_path: &Path) -> Result<()> {
    let preset_content = get_preset_content(name)?;

    // Parse preset
    let preset: toml::Value = toml::from_str(&preset_content)
        .with_context(|| format!("Failed to parse preset '{}'", name))?;

    // Read existing config (if it exists)
    let existing_content = if config_path.exists() {
        std::fs::read_to_string(config_path)
            .with_context(|| format!("Failed to read config: {}", config_path.display()))?
    } else {
        String::new()
    };

    // Backup existing config
    if config_path.exists() {
        let backup_path = config_path.with_extension("toml.backup");
        std::fs::copy(config_path, &backup_path)
            .with_context(|| format!("Failed to create backup: {}", backup_path.display()))?;
        println!("  Backup: {}", backup_path.display());
    }

    // Parse existing config (or start fresh)
    let mut config: toml::Value = if !existing_content.is_empty() {
        toml::from_str(&existing_content)
            .unwrap_or_else(|_| toml::Value::Table(toml::map::Map::new()))
    } else {
        toml::Value::Table(toml::map::Map::new())
    };

    let config_table = config
        .as_table_mut()
        .context("Config is not a TOML table")?;

    let preset_table = preset.as_table().context("Preset is not a TOML table")?;

    // Preserve [user] section from existing config
    let user_section = config_table.get("user").cloned();

    // Replace router, providers, models from preset
    if let Some(router) = preset_table.get("router") {
        config_table.insert("router".to_string(), router.clone());
    }
    if let Some(providers) = preset_table.get("providers") {
        config_table.insert("providers".to_string(), providers.clone());
    }
    if let Some(models) = preset_table.get("models") {
        config_table.insert("models".to_string(), models.clone());
    }

    // Restore [user] section
    if let Some(user) = user_section {
        config_table.insert("user".to_string(), user);
    }

    // Ensure [server] exists with defaults
    if !config_table.contains_key("server") {
        let mut server = toml::map::Map::new();
        server.insert(
            "host".to_string(),
            toml::Value::String("127.0.0.1".to_string()),
        );
        server.insert("port".to_string(), toml::Value::Integer(13456));
        server.insert(
            "log_level".to_string(),
            toml::Value::String("info".to_string()),
        );
        config_table.insert("server".to_string(), toml::Value::Table(server));
    }

    // Update presets.active
    let presets_section = config_table
        .entry("presets".to_string())
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));
    if let Some(table) = presets_section.as_table_mut() {
        table.insert("active".to_string(), toml::Value::String(name.to_string()));
    }

    // Write merged config
    let output = toml::to_string_pretty(&config).context("Failed to serialize merged config")?;
    std::fs::write(config_path, &output)
        .with_context(|| format!("Failed to write config: {}", config_path.display()))?;

    // Print summary
    println!("  Applied: {}", name);
    println!("  Config: {}", config_path.display());

    // Summarize what was configured
    if let Some(router) = preset_table.get("router").and_then(|r| r.as_table()) {
        println!();
        println!("  Router:");
        if let Some(v) = router.get("default").and_then(|v| v.as_str()) {
            println!("    Default:    {}", v);
        }
        if let Some(v) = router.get("think").and_then(|v| v.as_str()) {
            println!("    Think:      {}", v);
        }
        if let Some(v) = router.get("background").and_then(|v| v.as_str()) {
            println!("    Background: {}", v);
        }
        if let Some(v) = router.get("websearch").and_then(|v| v.as_str()) {
            println!("    WebSearch:  {}", v);
        }
    }

    if let Some(providers) = preset_table.get("providers").and_then(|p| p.as_array()) {
        println!();
        println!("  Providers ({}):", providers.len());
        for p in providers {
            if let Some(name) = p.get("name").and_then(|n| n.as_str()) {
                let ptype = p
                    .get("provider_type")
                    .and_then(|t| t.as_str())
                    .unwrap_or("?");
                let key = p.get("api_key").and_then(|k| k.as_str()).unwrap_or("");
                let auth = p
                    .get("auth_type")
                    .and_then(|a| a.as_str())
                    .unwrap_or("api_key");
                let auth_info = if auth == "oauth" {
                    " (oauth)".to_string()
                } else if key.starts_with('$') {
                    format!(" ({})", key)
                } else {
                    String::new()
                };
                println!("    {} ({}){}", name, ptype, auth_info);
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Credential wizard: detect + prompt for missing auth after preset apply
// ---------------------------------------------------------------------------

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
/// If `filter_provider` is Some, only process that specific provider.
pub fn setup_credentials_interactive(config_path: &Path) -> Result<()> {
    setup_credentials_interactive_filtered(config_path, None)
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
        // Only prompt for API key providers (OAuth needs the server running)
        if status.detail.contains("OAuth") {
            println!(
                "  {} — OAuth will be set up on first `grob start`",
                status.provider_name
            );
            continue;
        }

        println!("  {} ({}):", status.provider_name, status.provider_type);
        println!("    [1] Enter API key now");
        println!("    [2] I'll set the env var later");
        println!("    [3] Skip (disable this provider)");
        print!("    > ");

        // Flush stdout before reading
        use std::io::Write;
        std::io::stdout().flush()?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let choice = input.trim();

        match choice {
            "1" => {
                print!("    API key: ");
                std::io::stdout().flush()?;
                let mut key = String::new();
                std::io::stdin().read_line(&mut key)?;
                let key = key.trim().to_string();

                if key.is_empty() {
                    println!("    Skipped (empty input)");
                    continue;
                }

                // Write key directly into config
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
                config_changed = true;
                println!("    ✅ Saved to config");
            }
            "3" => {
                // Disable provider
                if let Some(providers) = config.get_mut("providers").and_then(|p| p.as_array_mut())
                {
                    for provider in providers.iter_mut() {
                        let pname = provider.get("name").and_then(|n| n.as_str()).unwrap_or("");
                        if pname == status.provider_name {
                            if let Some(ptable) = provider.as_table_mut() {
                                ptable.insert("enabled".to_string(), toml::Value::Boolean(false));
                            }
                        }
                    }
                }
                config_changed = true;
                println!("    Provider disabled");
            }
            _ => {
                // Default: will set env var later
                println!(
                    "    OK — set {} before running grob",
                    status
                        .detail
                        .split_whitespace()
                        .next()
                        .unwrap_or("the env var")
                );
            }
        }
        println!();
    }

    if config_changed {
        let output = toml::to_string_pretty(&config)?;
        std::fs::write(config_path, &output)?;
    }

    Ok(())
}

/// Export current config as a preset (strips [server], replaces API keys with env vars)
pub fn export_preset(name: &str, config_path: &Path) -> Result<()> {
    let content = std::fs::read_to_string(config_path)
        .with_context(|| format!("Failed to read config: {}", config_path.display()))?;

    let mut config: toml::Value = toml::from_str(&content)
        .with_context(|| format!("Failed to parse config: {}", config_path.display()))?;

    let table = config
        .as_table_mut()
        .context("Config is not a TOML table")?;

    // Remove server and presets sections
    table.remove("server");
    table.remove("presets");

    // Replace API keys with environment variable references
    if let Some(providers) = table.get_mut("providers").and_then(|p| p.as_array_mut()) {
        for provider in providers {
            if let Some(ptable) = provider.as_table_mut() {
                if ptable.get("api_key").is_some() {
                    let provider_name = ptable
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("UNKNOWN")
                        .to_uppercase()
                        .replace('-', "_");
                    let env_var = format!("${}_API_KEY", provider_name);
                    ptable.insert("api_key".to_string(), toml::Value::String(env_var));
                }
            }
        }
    }

    // Write to presets directory
    let dir = preset_dir()?;
    let output_path = dir.join(format!("{}.toml", name));
    let output = toml::to_string_pretty(&config).context("Failed to serialize preset")?;
    std::fs::write(&output_path, &output)
        .with_context(|| format!("Failed to write preset: {}", output_path.display()))?;

    println!("  Exported preset '{}' to {}", name, output_path.display());
    Ok(())
}

// ---------------------------------------------------------------------------
// Remote sync: HTTP fetch (no git required)
// ---------------------------------------------------------------------------

/// Index file format for a remote preset repository.
/// Place an `index.toml` at the root of your HTTP-served directory:
/// ```toml
/// files = ["perf.toml", "medium.toml", "cheap.toml"]
/// ```
#[derive(Deserialize)]
struct PresetIndex {
    files: Vec<String>,
}

/// Fetch text content from a URL.
async fn fetch_text(client: &reqwest::Client, url: &str) -> Result<String> {
    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("Failed to fetch {}", url))?;

    if !response.status().is_success() {
        anyhow::bail!("HTTP {} for {}", response.status(), url);
    }

    response
        .text()
        .await
        .with_context(|| format!("Failed to read response from {}", url))
}

/// Sync presets from any URL source.
/// - URL ending in `.toml` (not `index.toml`) → download single preset file
/// - URL ending in `/` or `index.toml` → download index, then fetch each listed file
/// - URL ending in `.git` or `git@` prefix → fallback to git clone (requires git)
pub async fn sync_presets(source: &str) -> Result<()> {
    if source.ends_with(".git") || source.starts_with("git@") || source.starts_with("git://") {
        // Git fallback (requires git installed)
        tracing::warn!("Using git for sync — consider using an HTTP URL instead");
        sync_from_git(source)
    } else {
        sync_from_url(source).await
    }
}

/// Sync presets via HTTP (no git required).
async fn sync_from_url(url: &str) -> Result<()> {
    let dest_dir = preset_dir()?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("Failed to create HTTP client")?;

    // Single .toml file download
    if url.ends_with(".toml") && !url.ends_with("/index.toml") {
        let filename = url.rsplit('/').next().unwrap_or("preset.toml");
        let content = fetch_text(&client, url).await?;
        // Validate it's parseable TOML
        let _: toml::Value = toml::from_str(&content)
            .with_context(|| format!("Downloaded file is not valid TOML: {}", url))?;
        let dest = dest_dir.join(filename);
        std::fs::write(&dest, &content)?;
        println!("  Downloaded: {}", filename);
        return Ok(());
    }

    // Directory-style: fetch index.toml then each listed file
    let base_url = if url.ends_with('/') {
        url.to_string()
    } else if url.ends_with("/index.toml") {
        url.trim_end_matches("index.toml").to_string()
    } else {
        format!("{}/", url)
    };

    let index_url = format!("{}index.toml", base_url);
    let index_content = fetch_text(&client, &index_url).await
        .with_context(|| format!("Failed to fetch index at {}. Either point to a single .toml file or provide a directory with index.toml", index_url))?;

    let index: PresetIndex = toml::from_str(&index_content)
        .context("Failed to parse index.toml (expected: files = [\"a.toml\", \"b.toml\"])")?;

    let mut count = 0;
    for file in &index.files {
        let file_url = format!("{}{}", base_url, file);
        match fetch_text(&client, &file_url).await {
            Ok(content) => {
                // Validate TOML before saving
                if toml::from_str::<toml::Value>(&content).is_err() {
                    eprintln!("  Warning: {} is not valid TOML, skipping", file);
                    continue;
                }
                let dest = dest_dir.join(file);
                std::fs::write(&dest, &content)?;
                println!("  Downloaded: {}", file);
                count += 1;
            }
            Err(e) => {
                eprintln!("  Warning: Failed to download {}: {}", file, e);
            }
        }
    }

    println!("  Synced {} preset(s) from {}", count, base_url);
    Ok(())
}

/// Install presets from a source (HTTP URL or local file/directory)
pub async fn install_from_source(source: &str) -> Result<()> {
    if source.starts_with("http://") || source.starts_with("https://") {
        // HTTP URL — fetch via reqwest
        sync_presets(source).await
    } else {
        // Local file or directory
        install_from_local(source)
    }
}

/// Install from a local file or directory.
fn install_from_local(source: &str) -> Result<()> {
    let dest_dir = preset_dir()?;
    let source_path = Path::new(source);

    if source_path.is_dir() {
        let mut count = 0;
        for entry in std::fs::read_dir(source_path)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("toml") {
                let dest = dest_dir.join(path.file_name().unwrap());
                std::fs::copy(&path, &dest)?;
                println!("  Installed: {}", dest.display());
                count += 1;
            }
        }
        println!("  {} preset(s) installed from {}", count, source);
    } else if source_path.is_file() {
        let dest = dest_dir.join(source_path.file_name().unwrap());
        std::fs::copy(source_path, &dest)?;
        println!("  Installed: {}", dest.display());
    } else {
        anyhow::bail!("Source not found: {}", source);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Git fallback (kept for git:// and .git URLs)
// ---------------------------------------------------------------------------

/// Sync presets from a git repository (requires git installed).
fn sync_from_git(repo_url: &str) -> Result<()> {
    let home = dirs::home_dir().context("Failed to get home directory")?;
    let repo_dir = home.join(".grob").join("presets-repo");
    let dest_dir = preset_dir()?;

    if repo_dir.exists() {
        println!("  Pulling latest presets...");
        let output = std::process::Command::new("git")
            .args(["pull", "--ff-only"])
            .current_dir(&repo_dir)
            .output()
            .context("Failed to run git — is git installed?")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!(
                "  Warning: git pull failed ({}), re-cloning...",
                stderr.trim()
            );
            std::fs::remove_dir_all(&repo_dir)?;
            clone_repo(repo_url, &repo_dir)?;
        }
    } else {
        clone_repo(repo_url, &repo_dir)?;
    }

    // Copy all .toml files from repo to presets dir
    let mut count = 0;
    for entry in std::fs::read_dir(&repo_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("toml") {
            let dest = dest_dir.join(path.file_name().unwrap());
            std::fs::copy(&path, &dest)?;
            count += 1;
        }
    }

    // Also check a presets/ subdirectory
    let repo_presets_subdir = repo_dir.join("presets");
    if repo_presets_subdir.is_dir() {
        for entry in std::fs::read_dir(&repo_presets_subdir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("toml") {
                let dest = dest_dir.join(path.file_name().unwrap());
                std::fs::copy(&path, &dest)?;
                count += 1;
            }
        }
    }

    println!("  Synced {} preset(s) from {}", count, repo_url);
    Ok(())
}

fn clone_repo(url: &str, dest: &Path) -> Result<()> {
    println!("  Cloning {}...", url);
    let output = std::process::Command::new("git")
        .args(["clone", "--depth", "1", url])
        .arg(dest)
        .output()
        .context("Failed to run git — is git installed?")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("git clone failed: {}", stderr.trim());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Background sync
// ---------------------------------------------------------------------------

/// Parse a human-readable interval string to seconds.
/// Supports: "30m", "6h", "1d", "12h", etc.
pub fn parse_interval(s: &str) -> Result<u64> {
    let s = s.trim();
    if s.is_empty() {
        anyhow::bail!("Empty interval string");
    }

    let (num_str, unit) = s.split_at(s.len() - 1);
    let num: u64 = num_str
        .parse()
        .with_context(|| format!("Invalid interval number: '{}'", num_str))?;

    match unit {
        "s" => Ok(num),
        "m" => Ok(num * 60),
        "h" => Ok(num * 3600),
        "d" => Ok(num * 86400),
        _ => anyhow::bail!("Unknown interval unit '{}'. Use s/m/h/d.", unit),
    }
}

/// Spawn a background sync loop that fetches presets at the given interval.
pub fn spawn_background_sync(source: String, interval_str: String) {
    let interval_secs = match parse_interval(&interval_str) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Invalid sync_interval '{}': {}", interval_str, e);
            return;
        }
    };

    tracing::info!(
        "Preset background sync: every {} ({}s) from {}",
        interval_str,
        interval_secs,
        source
    );

    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs)).await;

            tracing::info!("Syncing presets from {}...", source);
            match sync_presets(&source).await {
                Ok(_) => tracing::info!("Preset sync complete"),
                Err(e) => tracing::error!("Preset sync failed: {}", e),
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Config validation: smoke-test providers + models + fallback chains
// ---------------------------------------------------------------------------

use crate::auth::TokenStore;
use crate::cli::AppConfig;
use crate::models::{AnthropicRequest, Message, MessageContent};
use crate::providers::ProviderRegistry;
use std::sync::Arc;

/// Result of validating a single provider/model mapping
#[derive(Debug)]
pub struct MappingResult {
    pub priority: u32,
    pub provider: String,
    pub actual_model: String,
    pub ok: bool,
    pub detail: String,
}

/// Result of validating a router model (with all its fallback mappings)
#[derive(Debug)]
pub struct ModelValidation {
    pub model_name: String,
    pub role: String,
    pub mappings: Vec<MappingResult>,
}

impl ModelValidation {
    pub fn healthy_count(&self) -> usize {
        self.mappings.iter().filter(|m| m.ok).count()
    }
    pub fn all_ok(&self) -> bool {
        !self.mappings.is_empty() && self.mappings.iter().all(|m| m.ok)
    }
    pub fn any_ok(&self) -> bool {
        self.mappings.iter().any(|m| m.ok)
    }
}

/// Build a provider registry from config (for CLI validation path).
pub fn build_registry(config: &AppConfig) -> Result<(Arc<ProviderRegistry>, TokenStore)> {
    let token_store = TokenStore::at_default_path()
        .map_err(|e| anyhow::anyhow!("Failed to init token store: {}", e))?;

    let registry = Arc::new(
        ProviderRegistry::from_configs_with_models(
            &config.providers,
            Some(token_store.clone()),
            &config.models,
        )
        .map_err(|e| anyhow::anyhow!("Failed to init providers: {}", e))?,
    );

    Ok((registry, token_store))
}

/// Validate all router models by sending a minimal request to each provider mapping.
/// Tests auth, model availability, and fallback chains with real API calls.
pub async fn validate_config(
    config: &AppConfig,
    registry: &ProviderRegistry,
) -> Vec<ModelValidation> {
    // Collect router models to test
    let mut models_to_test: Vec<(&str, &str)> = vec![(&config.router.default, "default")];
    if let Some(ref m) = config.router.think {
        models_to_test.push((m, "think"));
    }
    if let Some(ref m) = config.router.background {
        models_to_test.push((m, "background"));
    }
    if let Some(ref m) = config.router.websearch {
        models_to_test.push((m, "websearch"));
    }

    // Deduplicate (a model can be used for multiple roles)
    let mut seen = std::collections::HashSet::new();
    models_to_test.retain(|(name, _)| seen.insert(*name));

    let mut results = Vec::new();

    for (model_name, role) in &models_to_test {
        let model_config = match config.models.iter().find(|m| m.name == *model_name) {
            Some(mc) => mc,
            None => {
                results.push(ModelValidation {
                    model_name: model_name.to_string(),
                    role: role.to_string(),
                    mappings: vec![MappingResult {
                        priority: 0,
                        provider: "?".to_string(),
                        actual_model: "?".to_string(),
                        ok: false,
                        detail: "Model not found in [[models]]".to_string(),
                    }],
                });
                continue;
            }
        };

        let mut sorted = model_config.mappings.clone();
        sorted.sort_by_key(|m| m.priority);

        let mut mapping_results = Vec::new();

        for mapping in &sorted {
            let provider = match registry.get_provider(&mapping.provider) {
                Some(p) => p,
                None => {
                    mapping_results.push(MappingResult {
                        priority: mapping.priority,
                        provider: mapping.provider.clone(),
                        actual_model: mapping.actual_model.clone(),
                        ok: false,
                        detail: "Provider not in registry".to_string(),
                    });
                    continue;
                }
            };

            let start = std::time::Instant::now();
            let test_req = make_test_request(&mapping.actual_model);

            let result = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                provider.send_message(test_req),
            )
            .await;

            let latency = start.elapsed().as_millis() as u64;

            match result {
                Ok(Ok(_)) => {
                    mapping_results.push(MappingResult {
                        priority: mapping.priority,
                        provider: mapping.provider.clone(),
                        actual_model: mapping.actual_model.clone(),
                        ok: true,
                        detail: format!("OK ({}ms)", latency),
                    });
                }
                Ok(Err(e)) => {
                    let err_str = e.to_string();
                    // Truncate long errors
                    let short = if err_str.len() > 80 {
                        format!("{}...", &err_str[..77])
                    } else {
                        err_str
                    };
                    mapping_results.push(MappingResult {
                        priority: mapping.priority,
                        provider: mapping.provider.clone(),
                        actual_model: mapping.actual_model.clone(),
                        ok: false,
                        detail: short,
                    });
                }
                Err(_) => {
                    mapping_results.push(MappingResult {
                        priority: mapping.priority,
                        provider: mapping.provider.clone(),
                        actual_model: mapping.actual_model.clone(),
                        ok: false,
                        detail: "Timeout (30s)".to_string(),
                    });
                }
            }
        }

        results.push(ModelValidation {
            model_name: model_name.to_string(),
            role: role.to_string(),
            mappings: mapping_results,
        });
    }

    results
}

/// Create a minimal test request (max_tokens=1, single short message).
fn make_test_request(model: &str) -> AnthropicRequest {
    AnthropicRequest {
        model: model.to_string(),
        messages: vec![Message {
            role: "user".to_string(),
            content: MessageContent::Text("Say OK".to_string()),
        }],
        max_tokens: 1,
        thinking: None,
        temperature: None,
        top_p: None,
        top_k: None,
        stop_sequences: None,
        stream: None,
        metadata: None,
        system: None,
        tools: None,
        tool_choice: None,
    }
}

/// Print validation results to stdout.
pub fn print_validation_results(results: &[ModelValidation]) {
    let all_ok = results.iter().all(|r| r.any_ok());

    for r in results {
        let healthy = r.healthy_count();
        let total = r.mappings.len();
        let icon = if r.all_ok() {
            "✅"
        } else if r.any_ok() {
            "⚠️"
        } else {
            "❌"
        };

        println!(
            "  {} {} [{}] — {}/{} mappings healthy",
            icon, r.model_name, r.role, healthy, total
        );

        for m in &r.mappings {
            let status = if m.ok { "✅" } else { "❌" };
            println!(
                "    [{}] {}/{}: {} {}",
                m.priority, m.provider, m.actual_model, status, m.detail
            );
        }
    }

    println!();
    if all_ok {
        println!("  All models have at least one healthy provider.");
    } else {
        let broken: Vec<&str> = results
            .iter()
            .filter(|r| !r.any_ok())
            .map(|r| r.model_name.as_str())
            .collect();
        if !broken.is_empty() {
            println!(
                "  ❌ Models with NO healthy providers: {}",
                broken.join(", ")
            );
            println!("     These will fail at runtime. Check credentials and model names.");
        }
    }
}

/// Log validation results (for server startup / reload).
pub fn log_validation_results(results: &[ModelValidation]) {
    for r in results {
        let healthy = r.healthy_count();
        let total = r.mappings.len();

        if r.all_ok() {
            tracing::info!("✅ {} [{}]: {}/{} OK", r.model_name, r.role, healthy, total);
        } else if r.any_ok() {
            tracing::warn!(
                "⚠️ {} [{}]: {}/{} OK (some fallbacks broken)",
                r.model_name,
                r.role,
                healthy,
                total
            );
            for m in &r.mappings {
                if !m.ok {
                    tracing::warn!(
                        "  ❌ [{}] {}/{}: {}",
                        m.priority,
                        m.provider,
                        m.actual_model,
                        m.detail
                    );
                }
            }
        } else {
            tracing::error!(
                "❌ {} [{}]: 0/{} — ALL providers failed!",
                r.model_name,
                r.role,
                total
            );
            for m in &r.mappings {
                tracing::error!(
                    "  ❌ [{}] {}/{}: {}",
                    m.priority,
                    m.provider,
                    m.actual_model,
                    m.detail
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_interval() {
        assert_eq!(parse_interval("30m").unwrap(), 1800);
        assert_eq!(parse_interval("6h").unwrap(), 21600);
        assert_eq!(parse_interval("1d").unwrap(), 86400);
        assert_eq!(parse_interval("90s").unwrap(), 90);
        assert!(parse_interval("").is_err());
        assert!(parse_interval("abc").is_err());
    }

    #[test]
    fn test_list_presets_contains_builtins() {
        let presets = list_presets().unwrap();
        let names: Vec<&str> = presets.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"perf"));
        assert!(names.contains(&"medium"));
        assert!(names.contains(&"local"));
        assert!(names.contains(&"cheap"));
        assert!(names.contains(&"fast"));
    }

    #[test]
    fn test_get_builtin_preset_content() {
        let content = get_preset_content("perf").unwrap();
        assert!(content.contains("[router]"));
        assert!(content.contains("[[providers]]"));

        let content = get_preset_content("medium").unwrap();
        assert!(content.contains("[router]"));

        let content = get_preset_content("cheap").unwrap();
        assert!(content.contains("deepseek"));

        let content = get_preset_content("fast").unwrap();
        assert!(content.contains("anthropic"));
    }

    #[test]
    fn test_get_nonexistent_preset() {
        assert!(get_preset_content("nonexistent-xyz-999").is_err());
    }

    #[test]
    fn test_builtin_presets_parse_as_valid_toml() {
        for (name, content) in [
            ("perf", BUILTIN_PERF),
            ("medium", BUILTIN_MEDIUM),
            ("local", BUILTIN_LOCAL),
            ("cheap", BUILTIN_CHEAP),
            ("fast", BUILTIN_FAST),
        ] {
            let parsed: Result<toml::Value, _> = toml::from_str(content);
            assert!(
                parsed.is_ok(),
                "Preset '{}' failed to parse as TOML: {:?}",
                name,
                parsed.err()
            );

            let table = parsed.unwrap();
            assert!(
                table.get("router").is_some(),
                "Preset '{}' missing [router]",
                name
            );
            assert!(
                table.get("providers").is_some(),
                "Preset '{}' missing [[providers]]",
                name
            );
            assert!(
                table.get("models").is_some(),
                "Preset '{}' missing [[models]]",
                name
            );
        }
    }

    #[test]
    fn test_apply_preset_to_temp_config() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");

        // Write a minimal existing config with [server]
        std::fs::write(
            &config_path,
            r#"
[server]
host = "127.0.0.1"
port = 9999
log_level = "debug"

[router]
default = "old-model"
"#,
        )
        .unwrap();

        // Apply radin preset
        apply_preset("cheap", &config_path).unwrap();

        // Verify backup was created
        assert!(config_path.with_extension("toml.backup").exists());

        // Verify config was updated
        let content = std::fs::read_to_string(&config_path).unwrap();

        // Server section should be preserved
        assert!(content.contains("9999"), "Server port should be preserved");

        // Router should come from preset
        assert!(
            content.contains("think-model"),
            "Think model should come from preset"
        );

        // Presets.active should be set
        assert!(
            content.contains("cheap"),
            "Active preset should be recorded"
        );
    }
}

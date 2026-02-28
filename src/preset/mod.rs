//! Preset management: builtin/installed presets, apply, export, credential wizard, sync, validation.

mod credentials;
mod sync;
mod validation;

// Re-export public API
pub use credentials::{
    check_credentials, load_oauth_provider_list_pub, setup_credentials_interactive,
    setup_credentials_interactive_filtered, CredentialStatus,
};
pub use sync::{install_from_source, parse_interval, spawn_background_sync, sync_presets};
pub use validation::{
    build_registry, log_validation_results, print_validation_results, validate_config,
    MappingResult, ModelValidation,
};

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

const BUILTIN_PERF: &str = include_str!("../../presets/perf.toml");
const BUILTIN_MEDIUM: &str = include_str!("../../presets/medium.toml");
const BUILTIN_LOCAL: &str = include_str!("../../presets/local.toml");
const BUILTIN_CHEAP: &str = include_str!("../../presets/cheap.toml");
const BUILTIN_FAST: &str = include_str!("../../presets/fast.toml");
const BUILTIN_GDPR: &str = include_str!("../../presets/gdpr.toml");
const BUILTIN_EU_AI_ACT: &str = include_str!("../../presets/eu-ai-act.toml");

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

/// Scan providers in a parsed preset TOML to collect env var requirements and flags.
fn collect_preset_requirements(preset: &toml::Value) -> (Vec<String>, bool, bool) {
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

    (env_vars, needs_oauth, needs_ollama)
}

/// Print the requirements section for a preset info display.
fn print_requirements_section(env_vars: &[String], needs_oauth: bool, needs_ollama: bool) {
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
    for var in env_vars {
        let set = std::env::var(var).is_ok();
        let icon = if set { "✅" } else { "⚠️" };
        println!(
            "   {} {} {}",
            icon,
            var,
            if set { "(set)" } else { "(not set)" }
        );
    }
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

    let (env_vars, needs_oauth, needs_ollama) = collect_preset_requirements(&preset);
    print_requirements_section(&env_vars, needs_oauth, needs_ollama);

    Ok(())
}

/// Merge preset sections (router, providers, models) into config, preserving [user].
fn merge_preset_into_config(
    config_table: &mut toml::map::Map<String, toml::Value>,
    preset_table: &toml::map::Map<String, toml::Value>,
) {
    let user_section = config_table.get("user").cloned();

    if let Some(router) = preset_table.get("router") {
        config_table.insert("router".to_string(), router.clone());
    }
    if let Some(providers) = preset_table.get("providers") {
        config_table.insert("providers".to_string(), providers.clone());
    }
    if let Some(models) = preset_table.get("models") {
        config_table.insert("models".to_string(), models.clone());
    }

    if let Some(user) = user_section {
        config_table.insert("user".to_string(), user);
    }
}

/// Ensure the [server] section exists with sensible defaults.
fn ensure_server_defaults(config_table: &mut toml::map::Map<String, toml::Value>) {
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

    merge_preset_into_config(config_table, preset_table);
    ensure_server_defaults(config_table);

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

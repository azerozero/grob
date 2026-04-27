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
use include_dir::{include_dir, Dir};
use std::path::{Path, PathBuf};

/// Builtin presets are auto-discovered from the `presets/` directory at
/// compile time. Adding/removing a preset = touch its `.toml` only; no
/// Rust code change needed. Each preset's description comes from its
/// `[meta] description = "..."` section.
static BUILTIN_PRESETS: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/presets");

/// Metadata for a builtin or installed preset.
#[derive(Debug)]
pub struct PresetInfo {
    /// Short unique preset identifier.
    pub name: String,
    /// Human-readable summary of the preset.
    pub description: String,
    /// True if shipped with the binary, false if user-installed.
    pub is_builtin: bool,
}

/// Returns the presets directory path (`~/.grob/presets/`).
///
/// # Errors
///
/// Returns an error if the home directory cannot be determined or
/// the presets directory cannot be created.
pub fn preset_dir() -> Result<PathBuf> {
    let dir = crate::grob_home()
        .context("Failed to get home directory (set GROB_HOME)")?
        .join("presets");
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("Failed to create presets directory: {}", dir.display()))?;
    Ok(dir)
}

/// Reads the `[meta] description` field from a preset TOML body.
/// Falls back to a generic label when the field is absent or unparseable.
fn parse_description(body: &str, fallback: &str) -> String {
    toml::from_str::<toml::Value>(body)
        .ok()
        .and_then(|v| {
            v.get("meta")
                .and_then(|m| m.get("description"))
                .and_then(|d| d.as_str())
                .map(str::to_owned)
        })
        .unwrap_or_else(|| fallback.to_string())
}

/// Lists all available presets (builtins + installed).
///
/// Builtins are auto-discovered from the embedded `presets/` directory.
/// Installed presets in `~/.grob/presets/` shadow builtins of the same
/// name (allowing local overrides).
///
/// # Errors
///
/// Returns an error if the presets directory cannot be read.
pub fn list_presets() -> Result<Vec<PresetInfo>> {
    let mut presets: Vec<PresetInfo> = Vec::new();

    // Builtins: scan the embedded directory for *.toml files.
    // Skip `index.toml` (it's a sync manifest, not a preset).
    for file in BUILTIN_PRESETS.files() {
        let path = file.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let stem = path.file_stem().and_then(|n| n.to_str()).unwrap_or("");
        if stem.is_empty() || stem == "index" {
            continue;
        }
        let body = file.contents_utf8().unwrap_or("");
        let description = parse_description(body, "Builtin preset");
        presets.push(PresetInfo {
            name: stem.to_string(),
            description,
            is_builtin: true,
        });
    }

    // Installed presets: scan ~/.grob/presets/ for *.toml files. Shadow
    // builtins of the same name (local override semantics).
    let dir = preset_dir()?;
    if dir.exists() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                continue;
            }
            let name = path
                .file_stem()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string();
            if presets.iter().any(|p| p.name == name) {
                continue;
            }
            let description = std::fs::read_to_string(&path)
                .ok()
                .map(|b| parse_description(&b, "Installed preset"))
                .unwrap_or_else(|| "Installed preset".to_string());
            presets.push(PresetInfo {
                name,
                description,
                is_builtin: false,
            });
        }
    }

    Ok(presets)
}

/// Gets preset content by name (builtin or installed file).
///
/// Builtins are read from the embedded directory; installed presets
/// from `~/.grob/presets/`. Builtins win on name collision.
///
/// # Errors
///
/// Returns an error if the preset name is not recognized as a
/// builtin and no installed file exists for it.
pub fn preset_content(name: &str) -> Result<String> {
    // Builtins first (embedded at compile time).
    let builtin_path = format!("{}.toml", name);
    if let Some(file) = BUILTIN_PRESETS.get_file(&builtin_path) {
        if let Some(body) = file.contents_utf8() {
            return Ok(body.to_string());
        }
    }

    // Fallback: ~/.grob/presets/<name>.toml.
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

/// Prints the "Requirements" block (OAuth, Ollama, env vars with set/unset status) shown by `grob preset info`.
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

/// Prints detailed info about a preset (providers, models, env vars, routing).
///
/// # Errors
///
/// Returns an error if the preset cannot be loaded or its TOML
/// content cannot be parsed.
pub fn print_preset_info(name: &str) -> Result<()> {
    let content = preset_content(name)?;
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
                match p.get("api_key").and_then(|k| k.as_str()).unwrap_or("") {
                    key if key.starts_with('$') => format!("env: {}", key),
                    key if !key.is_empty() => "API key (configured)".to_string(),
                    _ => "no key".to_string(),
                }
            };

            // SAFETY: auth_info contains only provider type labels (e.g. "OAuth (anthropic-max)") or
            // redacted status like "API key (configured)", never actual secrets.
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

/// Merge preset sections (router, providers, models, security, compliance, dlp) into config, preserving [user].
fn merge_preset_into_config(
    config_table: &mut toml::map::Map<String, toml::Value>,
    preset_table: &toml::map::Map<String, toml::Value>,
) {
    let user_section = config_table.get("user").cloned();

    for section in &[
        "router",
        "providers",
        "models",
        "security",
        "compliance",
        "dlp",
    ] {
        if let Some(value) = preset_table.get(*section) {
            config_table.insert(section.to_string(), value.clone());
        }
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

/// Applies a preset to the config file.
///
/// Keeps `[server]` and `[presets]` sections, replaces `[router]` +
/// `[[providers]]` + `[[models]]`.
///
/// # Errors
///
/// Returns an error if the preset cannot be loaded, the existing
/// config cannot be read/parsed, or the merged config cannot be
/// written.
pub fn apply_preset(name: &str, config_path: &Path) -> Result<()> {
    let preset_content = preset_content(name)?;

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

/// Previews a preset merge without writing to disk.
///
/// Returns the merged TOML as a string for display.
///
/// # Errors
///
/// Returns an error if the preset or existing config cannot be
/// loaded or parsed.
pub fn preview_preset(name: &str, config_path: &Path) -> Result<String> {
    let preset_content_str = preset_content(name)?;
    let preset: toml::Value = toml::from_str(&preset_content_str)
        .with_context(|| format!("Failed to parse preset '{}'", name))?;

    let existing_content = if config_path.exists() {
        std::fs::read_to_string(config_path)
            .with_context(|| format!("Failed to read config: {}", config_path.display()))?
    } else {
        String::new()
    };

    let mut config: toml::Value = if existing_content.is_empty() {
        toml::Value::Table(toml::map::Map::new())
    } else {
        toml::from_str(&existing_content)
            .with_context(|| format!("Failed to parse config: {}", config_path.display()))?
    };

    if let (Some(config_table), Some(preset_table)) = (config.as_table_mut(), preset.as_table()) {
        merge_preset_into_config(config_table, preset_table);
    }

    toml::to_string_pretty(&config).context("Failed to serialize preview")
}

/// Merges only compliance sections from a preset without replacing router/providers/models.
///
/// Overlays `[security]`, `[compliance]`, `[dlp]` from the named preset onto the
/// existing config. Router flags `gdpr` and `region` are merged without
/// replacing model assignments.
///
/// # Errors
///
/// Returns an error if the preset or config file cannot be read,
/// parsed, or the merged result cannot be written.
pub fn overlay_compliance(name: &str, config_path: &Path) -> Result<()> {
    let content = preset_content(name)?;
    let preset: toml::Value = toml::from_str(&content)
        .with_context(|| format!("Failed to parse compliance preset '{}'", name))?;
    let existing = std::fs::read_to_string(config_path)
        .with_context(|| format!("Failed to read config: {}", config_path.display()))?;
    let mut config: toml::Value = toml::from_str(&existing)
        .with_context(|| format!("Failed to parse config: {}", config_path.display()))?;

    let config_table = config
        .as_table_mut()
        .context("Config is not a TOML table")?;
    let preset_table = preset.as_table().context("Preset is not a TOML table")?;

    // Merge compliance sections only
    for section in &["security", "compliance", "dlp"] {
        if let Some(value) = preset_table.get(*section) {
            config_table.insert(section.to_string(), value.clone());
        }
    }

    // Merge router flags (gdpr, region) without replacing model assignments
    if let Some(new_router) = preset_table.get("router").and_then(|r| r.as_table()) {
        let existing_router = config_table
            .entry("router".to_string())
            .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));
        if let Some(router_table) = existing_router.as_table_mut() {
            for (k, v) in new_router {
                if matches!(k.as_str(), "gdpr" | "region") {
                    router_table.insert(k.clone(), v.clone());
                }
            }
        }
    }

    let output = toml::to_string_pretty(&config).context("Failed to serialize config")?;
    std::fs::write(config_path, &output)
        .with_context(|| format!("Failed to write config: {}", config_path.display()))?;
    Ok(())
}

/// Exports current config as a preset (strips `[server]`, replaces API keys with env vars).
///
/// # Errors
///
/// Returns an error if the config file cannot be read/parsed or the
/// preset file cannot be written.
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
        let tmp = std::env::temp_dir().join("grob-test-presets");
        #[allow(unsafe_code)]
        unsafe {
            std::env::set_var("GROB_HOME", &tmp);
        }
        let presets = list_presets().unwrap();
        #[allow(unsafe_code)]
        unsafe {
            std::env::remove_var("GROB_HOME");
        }
        let names: Vec<&str> = presets.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"perf"));
        assert!(names.contains(&"ultra-cheap"));
        assert!(names.contains(&"eu-eco"));
        assert!(names.contains(&"eu-pro"));
        assert!(names.contains(&"eu-max"));
    }

    #[test]
    fn test_get_builtin_preset_content() {
        let content = preset_content("perf").unwrap();
        assert!(content.contains("[router]"));
        assert!(content.contains("[[providers]]"));

        let content = preset_content("ultra-cheap").unwrap();
        assert!(content.contains("[router]"));
        assert!(content.contains("groq"));

        let content = preset_content("eu-pro").unwrap();
        assert!(content.contains("nebius"));

        let content = preset_content("eu-max").unwrap();
        assert!(content.contains("scaleway"));
    }

    #[test]
    fn test_get_nonexistent_preset() {
        assert!(preset_content("nonexistent-xyz-999").is_err());
    }

    #[test]
    fn test_builtin_presets_parse_as_valid_toml() {
        // Iterate the embedded directory directly — every shipped preset
        // (except the index manifest) must be valid TOML with the three
        // required top-level sections.
        for file in BUILTIN_PRESETS.files() {
            let path = file.path();
            if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                continue;
            }
            let stem = path.file_stem().and_then(|n| n.to_str()).unwrap_or("");
            if stem == "index" || stem.is_empty() {
                continue;
            }
            let content = file.contents_utf8().unwrap_or("");
            let parsed: Result<toml::Value, _> = toml::from_str(content);
            assert!(
                parsed.is_ok(),
                "Preset '{}' failed to parse as TOML: {:?}",
                stem,
                parsed.err()
            );

            let table = parsed.unwrap();
            assert!(
                table.get("router").is_some(),
                "Preset '{}' missing [router]",
                stem
            );
            assert!(
                table.get("providers").is_some(),
                "Preset '{}' missing [[providers]]",
                stem
            );
            // [[models]] is optional — presets that rely entirely on
            // auto_map_regex (e.g. `perf`) don't need explicit virtual
            // model definitions.
            assert!(
                table
                    .get("meta")
                    .and_then(|m| m.get("description"))
                    .and_then(|d| d.as_str())
                    .is_some(),
                "Preset '{}' missing [meta] description",
                stem
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

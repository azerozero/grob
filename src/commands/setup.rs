//! Interactive first-run setup wizard.
//!
//! Guides new users through tool selection, provider auth, compliance,
//! budget, and credential configuration when no `config.toml` exists.

use anyhow::Result;
use std::io::{self, Write};
use std::path::Path;

/// Known coding tools that grob can proxy.
const TOOLS: &[ToolInfo] = &[
    ToolInfo {
        name: "Claude Code",
        tag: "anthropic",
        endpoint: "/v1/messages",
        needs_anthropic: true,
        needs_openai: false,
    },
    ToolInfo {
        name: "Codex CLI",
        tag: "openai",
        endpoint: "/v1/responses",
        needs_anthropic: false,
        needs_openai: true,
    },
    ToolInfo {
        name: "Forge",
        tag: "anthropic",
        endpoint: "/v1/messages",
        needs_anthropic: true,
        needs_openai: false,
    },
    ToolInfo {
        name: "Aider",
        tag: "any",
        endpoint: "/v1/messages or /v1/chat/completions",
        needs_anthropic: true,
        needs_openai: false,
    },
    ToolInfo {
        name: "Continue.dev",
        tag: "any",
        endpoint: "/v1/messages or /v1/chat/completions",
        needs_anthropic: true,
        needs_openai: false,
    },
    ToolInfo {
        name: "Cursor",
        tag: "openai",
        endpoint: "/v1/chat/completions (BYOK)",
        needs_anthropic: false,
        needs_openai: true,
    },
];

struct ToolInfo {
    name: &'static str,
    tag: &'static str,
    endpoint: &'static str,
    needs_anthropic: bool,
    needs_openai: bool,
}

/// Auth capabilities for a provider.
struct ProviderAuthOption {
    provider_name: &'static str,
    supports_oauth: bool,
    oauth_provider_id: &'static str,
    env_var: &'static str,
}

const PROVIDER_AUTH_OPTIONS: &[ProviderAuthOption] = &[
    ProviderAuthOption {
        provider_name: "anthropic",
        supports_oauth: true,
        oauth_provider_id: "anthropic-max",
        env_var: "ANTHROPIC_API_KEY",
    },
    ProviderAuthOption {
        provider_name: "openai",
        supports_oauth: true,
        oauth_provider_id: "openai-codex",
        env_var: "OPENAI_API_KEY",
    },
    ProviderAuthOption {
        provider_name: "gemini",
        supports_oauth: true,
        oauth_provider_id: "gemini",
        env_var: "GEMINI_API_KEY",
    },
    ProviderAuthOption {
        provider_name: "openrouter",
        supports_oauth: false,
        oauth_provider_id: "",
        env_var: "OPENROUTER_API_KEY",
    },
    ProviderAuthOption {
        provider_name: "deepseek",
        supports_oauth: false,
        oauth_provider_id: "",
        env_var: "DEEPSEEK_API_KEY",
    },
    ProviderAuthOption {
        provider_name: "mistral",
        supports_oauth: false,
        oauth_provider_id: "",
        env_var: "MISTRAL_API_KEY",
    },
];

/// Overrides collected from the auth selection screen.
struct ProviderOverride {
    provider_name: String,
    use_oauth: bool,
    oauth_provider_id: String,
    api_key: Option<String>,
}

/// Prompts the user to select tools (comma-separated numbers).
fn prompt_multi_select(max: usize) -> Vec<usize> {
    loop {
        print!("  > ");
        io::stdout().flush().ok();
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            continue;
        }
        let trimmed = input.trim();

        // "all" shortcut
        if trimmed.eq_ignore_ascii_case("all") {
            return (0..max).collect();
        }

        let parsed: Vec<usize> = trimmed
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|s| !s.is_empty())
            .filter_map(|s| s.trim().parse::<usize>().ok())
            .filter(|&n| n >= 1 && n <= max)
            .map(|n| n - 1) // convert to 0-based
            .collect();

        if !parsed.is_empty() {
            return parsed;
        }
        println!("  Enter tool numbers separated by commas (e.g. 1,3) or 'all'");
    }
}

/// Reads a single line from stdin, trimmed.
fn read_line() -> String {
    let mut input = String::new();
    io::stdin().read_line(&mut input).ok();
    input.trim().to_string()
}

/// Reads a single-choice selection (1-based).
fn prompt_single_choice(max: usize) -> usize {
    loop {
        print!("  > ");
        io::stdout().flush().ok();
        let input = read_line();
        if let Ok(n) = input.parse::<usize>() {
            if n >= 1 && n <= max {
                return n;
            }
        }
        println!("  Enter a number between 1 and {}", max);
    }
}

/// Runs the interactive setup wizard.
///
/// Returns `true` if a config was written (caller should proceed),
/// `false` if the user cancelled.
pub fn run_setup_wizard(config_path: &Path) -> Result<bool> {
    println!();
    println!("Welcome to Grob! No configuration detected.");
    println!();

    // ── Screen 1: Tool selection ──
    println!("Which tools will you route through Grob?");
    println!("  (enter numbers separated by commas, e.g. 1,3)");
    println!();

    for (i, tool) in TOOLS.iter().enumerate() {
        println!(
            "  [{}] {:<16} {} {}",
            i + 1,
            tool.name,
            tool.tag,
            tool.endpoint
        );
    }
    println!();
    println!(
        "  [{}] Custom setup (I'll configure manually)",
        TOOLS.len() + 1
    );
    println!();

    let input = prompt_multi_select(TOOLS.len() + 1);
    let custom_idx = TOOLS.len();
    if input.contains(&custom_idx) {
        return setup_custom(config_path);
    }

    let selected: Vec<&ToolInfo> = input.iter().filter_map(|&i| TOOLS.get(i)).collect();

    if selected.is_empty() {
        println!("  No tools selected.");
        return Ok(false);
    }

    let needs_anthropic = selected.iter().any(|t| t.needs_anthropic);
    let needs_openai = selected.iter().any(|t| t.needs_openai);

    // Pick the best preset based on provider needs
    let (preset, description) = if needs_anthropic && needs_openai {
        ("fast", "Anthropic + OpenAI + Gemini + OpenRouter")
    } else if needs_openai {
        ("fast", "OpenAI + OpenRouter (pass-through)")
    } else {
        ("perf", "Anthropic OAuth + OpenRouter fallback")
    };

    let tool_names: Vec<&str> = selected.iter().map(|t| t.name).collect();
    println!();
    println!("Setting up for {}...", tool_names.join(" + "));
    println!("  Preset: {} ({})", preset, description);

    // Apply base preset
    crate::preset::apply_preset(preset, config_path)?;

    // ── Screen 2: Provider & Auth ──
    let providers_in_preset = collect_provider_names(config_path);
    let overrides = prompt_provider_auth(&providers_in_preset, config_path)?;
    apply_auth_overrides(config_path, &overrides)?;

    // ── Screen 3: Fallback ──
    let primary_count = providers_in_preset
        .iter()
        .filter(|p| *p != "openrouter")
        .count();
    let has_openrouter = providers_in_preset.iter().any(|p| p == "openrouter");
    if primary_count <= 1 && !has_openrouter {
        prompt_fallback(config_path)?;
    }

    // ── Screen 4: Compliance ──
    prompt_compliance(config_path, &selected)?;

    // ── Screen 5: Budget ──
    prompt_budget(config_path)?;

    // ── Screen 6: Validation ──
    print_provider_status(config_path);

    let tool_keys: Vec<&str> = selected
        .iter()
        .map(|t| match t.name {
            "Claude Code" => "claude",
            "Codex CLI" => "codex",
            "Forge" => "forge",
            "Aider" => "aider",
            "Continue.dev" => "continue",
            "Cursor" => "cursor",
            _ => "",
        })
        .filter(|k| !k.is_empty())
        .collect();
    print_tool_instructions(&tool_keys);

    Ok(true)
}

/// Reads provider names from an already-written config file.
fn collect_provider_names(config_path: &Path) -> Vec<String> {
    let content = match std::fs::read_to_string(config_path) {
        Ok(c) => c,
        Err(_) => return vec![],
    };
    let config: toml::Value = match toml::from_str(&content) {
        Ok(v) => v,
        Err(_) => return vec![],
    };
    config
        .get("providers")
        .and_then(|p| p.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|p| {
                    let enabled = p.get("enabled").and_then(|e| e.as_bool()).unwrap_or(true);
                    if !enabled {
                        return None;
                    }
                    p.get("name").and_then(|n| n.as_str()).map(String::from)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Screen 2: Asks the user to choose OAuth vs API key for each provider.
fn prompt_provider_auth(
    providers_needed: &[String],
    _config_path: &Path,
) -> Result<Vec<ProviderOverride>> {
    if providers_needed.is_empty() {
        return Ok(vec![]);
    }

    println!();
    println!("  Provider authentication:");
    println!();

    let mut overrides = Vec::new();

    for provider_name in providers_needed {
        let auth_opt = PROVIDER_AUTH_OPTIONS
            .iter()
            .find(|a| a.provider_name == provider_name);

        let auth_opt = match auth_opt {
            Some(a) => a,
            None => continue, // Unknown provider, skip (e.g. ollama — no auth needed)
        };

        if auth_opt.supports_oauth {
            println!("  {}:", provider_name);
            println!("    [1] OAuth (subscription — no API key needed) (Recommended)");
            println!("    [2] API key (${})", auth_opt.env_var);
            let choice = prompt_single_choice(2);

            if choice == 1 {
                overrides.push(ProviderOverride {
                    provider_name: provider_name.clone(),
                    use_oauth: true,
                    oauth_provider_id: auth_opt.oauth_provider_id.to_string(),
                    api_key: None,
                });
                println!("    OAuth selected — will prompt on first `grob start`");
            } else {
                let key = prompt_api_key(auth_opt.env_var);
                overrides.push(ProviderOverride {
                    provider_name: provider_name.clone(),
                    use_oauth: false,
                    oauth_provider_id: String::new(),
                    api_key: key,
                });
            }
            println!();
        } else {
            println!("  {}:", provider_name);
            println!("    [1] Enter API key now");
            println!("    [2] I'll set ${} later", auth_opt.env_var);
            let choice = prompt_single_choice(2);

            if choice == 1 {
                let key = prompt_api_key(auth_opt.env_var);
                overrides.push(ProviderOverride {
                    provider_name: provider_name.clone(),
                    use_oauth: false,
                    oauth_provider_id: String::new(),
                    api_key: key,
                });
            } else {
                println!("    OK — set ${} before running grob", auth_opt.env_var);
                // No override needed, keep env var reference from preset
            }
            println!();
        }
    }

    Ok(overrides)
}

/// Prompts for an API key, returns Some(key) or None if skipped.
fn prompt_api_key(env_var: &str) -> Option<String> {
    // Check if already set in environment
    if std::env::var(env_var).is_ok() {
        println!("    ${} already set in environment", env_var);
        return None;
    }
    print!("    API key: ");
    io::stdout().flush().ok();
    let key = read_line();
    if key.is_empty() {
        println!("    Skipped (empty input)");
        None
    } else {
        println!("    Saved to config");
        Some(key)
    }
}

/// Patches the TOML config to apply auth overrides (OAuth vs API key).
fn apply_auth_overrides(config_path: &Path, overrides: &[ProviderOverride]) -> Result<()> {
    if overrides.is_empty() {
        return Ok(());
    }

    let content = std::fs::read_to_string(config_path)?;
    let mut config: toml::Value = toml::from_str(&content)?;

    if let Some(providers) = config.get_mut("providers").and_then(|p| p.as_array_mut()) {
        for provider in providers.iter_mut() {
            let pname = provider.get("name").and_then(|n| n.as_str()).unwrap_or("");
            if let Some(ov) = overrides.iter().find(|o| o.provider_name == pname) {
                let ptable = match provider.as_table_mut() {
                    Some(t) => t,
                    None => continue,
                };
                if ov.use_oauth {
                    ptable.insert(
                        "auth_type".to_string(),
                        toml::Value::String("oauth".to_string()),
                    );
                    ptable.insert(
                        "oauth_provider".to_string(),
                        toml::Value::String(ov.oauth_provider_id.clone()),
                    );
                    ptable.remove("api_key");
                } else if let Some(ref key) = ov.api_key {
                    ptable.insert(
                        "auth_type".to_string(),
                        toml::Value::String("apikey".to_string()),
                    );
                    ptable.insert("api_key".to_string(), toml::Value::String(key.clone()));
                    ptable.remove("oauth_provider");
                }
            }
        }
    }

    let output = toml::to_string_pretty(&config)?;
    std::fs::write(config_path, &output)?;
    Ok(())
}

/// Screen 3: Suggests adding OpenRouter as a fallback provider.
fn prompt_fallback(config_path: &Path) -> Result<()> {
    println!();
    println!("  Add a fallback provider? (used if primary is down or rate-limited)");
    println!("    [1] OpenRouter (recommended — routes to 100+ models)");
    println!("    [2] No fallback");

    let choice = prompt_single_choice(2);
    if choice != 1 {
        return Ok(());
    }

    // Ask for API key
    let key = prompt_api_key("OPENROUTER_API_KEY");

    let content = std::fs::read_to_string(config_path)?;
    let mut config: toml::Value = toml::from_str(&content)?;

    // Add openrouter provider
    let mut or_table = toml::map::Map::new();
    or_table.insert(
        "name".to_string(),
        toml::Value::String("openrouter".to_string()),
    );
    or_table.insert(
        "provider_type".to_string(),
        toml::Value::String("openrouter".to_string()),
    );
    or_table.insert("pass_through".to_string(), toml::Value::Boolean(true));
    or_table.insert("enabled".to_string(), toml::Value::Boolean(true));
    or_table.insert("models".to_string(), toml::Value::Array(vec![]));

    if let Some(k) = key {
        or_table.insert("api_key".to_string(), toml::Value::String(k));
    } else {
        or_table.insert(
            "api_key".to_string(),
            toml::Value::String("$OPENROUTER_API_KEY".to_string()),
        );
    }

    if let Some(providers) = config.get_mut("providers").and_then(|p| p.as_array_mut()) {
        providers.push(toml::Value::Table(or_table));
    }

    let output = toml::to_string_pretty(&config)?;
    std::fs::write(config_path, &output)?;
    println!("    OpenRouter fallback added");
    println!();
    Ok(())
}

/// Screen 4: Compliance mode selection.
fn prompt_compliance(config_path: &Path, selected_tools: &[&ToolInfo]) -> Result<()> {
    println!();
    println!("  Security & compliance:");
    println!("    [1] Standard (default — all providers, no restrictions)");
    println!("    [2] DLP only (secret scanning + PII + prompt injection detection)");
    println!("    [3] GDPR (EU-only data residency + DLP)");
    println!("    [4] EU AI Act (GDPR + signed audit log + transparency + risk classification)");
    println!("    [5] Enterprise security (audit + DLP + rate limiting + OWASP headers)");
    println!("    [6] Local-only / air-gapped (Ollama — zero data transfer)");
    println!("    [7] Skip");

    let choice = prompt_single_choice(7);

    match choice {
        1 | 7 => {} // Standard or skip — nothing to do
        2 => {
            // DLP only
            patch_toml_section(config_path, "dlp", &[("enabled", TomlVal::Bool(true))])?;
            println!("    DLP enabled (secret scanning + PII + injection detection)");
        }
        3 => {
            // GDPR — check compatibility first
            let warnings = check_gdpr_compatibility(selected_tools);
            if !warnings.is_empty() {
                println!();
                println!("  GDPR compatibility notes:");
                for w in &warnings {
                    println!("    {}", w);
                }
                println!();
                print!("  Continue anyway? [y/N] ");
                io::stdout().flush().ok();
                let answer = read_line();
                if !answer.eq_ignore_ascii_case("y") && !answer.eq_ignore_ascii_case("yes") {
                    println!("    Skipped compliance configuration");
                    return Ok(());
                }
            }
            crate::preset::overlay_compliance("gdpr", config_path)?;
            println!("    GDPR mode applied (EU-only providers + DLP)");
        }
        4 => {
            // EU AI Act — includes GDPR warnings
            let warnings = check_gdpr_compatibility(selected_tools);
            if !warnings.is_empty() {
                println!();
                println!("  GDPR compatibility notes:");
                for w in &warnings {
                    println!("    {}", w);
                }
                println!();
                print!("  Continue anyway? [y/N] ");
                io::stdout().flush().ok();
                let answer = read_line();
                if !answer.eq_ignore_ascii_case("y") && !answer.eq_ignore_ascii_case("yes") {
                    println!("    Skipped compliance configuration");
                    return Ok(());
                }
            }
            crate::preset::overlay_compliance("eu-ai-act", config_path)?;
            println!("    EU AI Act mode applied (GDPR + audit + transparency + risk)");
        }
        5 => {
            // Enterprise security
            patch_toml_section(
                config_path,
                "security",
                &[
                    ("enabled", TomlVal::Bool(true)),
                    ("audit_dir", TomlVal::Str("~/.grob/audit")),
                    ("rate_limit_rps", TomlVal::Int(100)),
                    ("rate_limit_burst", TomlVal::Int(200)),
                    ("circuit_breaker", TomlVal::Bool(true)),
                    ("security_headers", TomlVal::Bool(true)),
                ],
            )?;
            patch_toml_section(config_path, "dlp", &[("enabled", TomlVal::Bool(true))])?;
            println!("    Enterprise security enabled (audit + DLP + rate limiting + OWASP)");
        }
        6 => {
            // Local-only — apply local preset entirely
            crate::preset::apply_preset("local", config_path)?;
            patch_toml_section(config_path, "security", &[("enabled", TomlVal::Bool(true))])?;
            patch_toml_section(config_path, "dlp", &[("enabled", TomlVal::Bool(true))])?;
            println!("    Local-only mode applied (Ollama + security + DLP)");
        }
        _ => {}
    }

    Ok(())
}

/// Checks GDPR compatibility for selected tools.
fn check_gdpr_compatibility(selected_tools: &[&ToolInfo]) -> Vec<String> {
    let mut warnings = Vec::new();
    for tool in selected_tools {
        match tool.name {
            "Claude Code" | "Forge" => {
                warnings.push(format!(
                    "{}: Anthropic does not guarantee EU-only processing. \
                     Alternative: route via OpenRouter EU (eu.openrouter.ai).",
                    tool.name
                ));
            }
            "Codex CLI" => {
                warnings.push(format!(
                    "{}: OpenAI supports EU data residency — verify your API project is set to EU region.",
                    tool.name
                ));
            }
            _ => {}
        }
    }
    warnings
}

/// Simple typed value for TOML patching.
enum TomlVal<'a> {
    Bool(bool),
    Int(i64),
    Str(&'a str),
}

/// Patches a top-level TOML section with key/value pairs (create if absent).
fn patch_toml_section(config_path: &Path, section: &str, fields: &[(&str, TomlVal)]) -> Result<()> {
    let content = std::fs::read_to_string(config_path)?;
    let mut config: toml::Value = toml::from_str(&content)?;

    let config_table = config
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("Config is not a TOML table"))?;

    let sec = config_table
        .entry(section.to_string())
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));

    if let Some(table) = sec.as_table_mut() {
        for (key, val) in fields {
            let v = match val {
                TomlVal::Bool(b) => toml::Value::Boolean(*b),
                TomlVal::Int(i) => toml::Value::Integer(*i),
                TomlVal::Str(s) => toml::Value::String(s.to_string()),
            };
            table.insert(key.to_string(), v);
        }
    }

    let output = toml::to_string_pretty(&config)?;
    std::fs::write(config_path, &output)?;
    Ok(())
}

/// Screen 5: Monthly budget cap.
fn prompt_budget(config_path: &Path) -> Result<()> {
    println!();
    println!("  Monthly budget cap:");
    println!("    [1] Unlimited (no limit)");
    println!("    [2] $50/month");
    println!("    [3] $200/month");
    println!("    [4] Custom amount");

    let choice = prompt_single_choice(4);

    let amount: Option<i64> = match choice {
        1 => None,
        2 => Some(50),
        3 => Some(200),
        4 => {
            print!("    Amount in USD: ");
            io::stdout().flush().ok();
            let input = read_line();
            input.parse::<i64>().ok()
        }
        _ => None,
    };

    if let Some(usd) = amount {
        patch_toml_section(
            config_path,
            "budget",
            &[
                ("monthly_limit_usd", TomlVal::Int(usd)),
                ("warn_at_percent", TomlVal::Int(80)),
            ],
        )?;
        println!("    Budget set to ${}/month (warning at 80%)", usd);
    } else {
        println!("    No budget limit set");
    }

    Ok(())
}

/// Screen 6: Print provider status after setup.
fn print_provider_status(config_path: &Path) {
    println!();
    println!("  Config written to {}", config_path.display());

    let statuses = match crate::preset::check_credentials(config_path) {
        Ok(s) => s,
        Err(_) => return,
    };

    println!();
    println!("  Provider status:");
    for status in &statuses {
        let auth_label = if status.detail.contains("OAuth") {
            "oauth"
        } else {
            "api_key"
        };
        let icon = if status.ok { "ok" } else { &status.detail };
        println!("    {} ({}) — {}", status.provider_name, auth_label, icon);
    }

    // Check if any OAuth providers need login
    let has_pending_oauth = statuses.iter().any(|s| !s.ok && s.detail.contains("OAuth"));
    if has_pending_oauth {
        println!();
        println!("  To complete OAuth setup, run:");
        println!("    grob start     (OAuth will trigger automatically in browser)");
        println!("    grob connect   (connect providers individually)");
    }
}

/// Custom setup — minimal config, user configures manually.
fn setup_custom(config_path: &Path) -> Result<bool> {
    println!();
    println!("Creating default config...");
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let minimal = concat!(
        "# Grob configuration\n",
        "# See available presets: grob preset list\n",
        "# Apply a preset:       grob preset apply <name>\n",
        "#\n",
        "# Or configure manually below.\n",
        "\n",
        "[server]\n",
        "port = 13456\n",
        "\n",
        "[router]\n",
        "default = \"default\"\n",
    );
    std::fs::write(config_path, minimal)?;
    println!();
    println!("  Config written to {}", config_path.display());
    println!();
    println!("  Next steps:");
    println!("    grob preset list          # See available presets");
    println!("    grob preset apply perf    # Apply a preset");
    println!("    grob connect              # Set up credentials");
    println!("    grob start -d             # Start the server");
    Ok(true)
}

/// Prints per-tool setup instructions showing how to launch each tool through grob.
fn print_tool_instructions(tools: &[&str]) {
    println!();
    println!("  How to use:");
    println!();

    for tool in tools {
        match *tool {
            "claude" => {
                println!("    Claude Code:");
                println!("      grob exec -- claude");
                println!();
            }
            "codex" => {
                println!("    Codex CLI (models: gpt-5.3-codex, gpt-5.4):");
                println!("      grob exec -- codex");
                println!("      # Or: OPENAI_BASE_URL=http://localhost:13456/v1 codex");
                println!();
            }
            "forge" => {
                println!("    Forge (default: claude-sonnet-4, or use claude-opus-4-6):");
                println!("      grob exec -- forge");
                println!("      # Or: ANTHROPIC_URL=http://localhost:13456/v1 forge");
                println!("      # In forge.yaml: model: anthropic_compatible/claude-opus-4-6");
                println!();
            }
            "aider" => {
                println!("    Aider:");
                println!("      grob exec -- aider");
                println!("      # Or: ANTHROPIC_BASE_URL=http://localhost:13456 aider");
                println!();
            }
            "continue" => {
                println!("    Continue.dev (in .continue/config.yaml):");
                println!("      apiBase: http://localhost:13456");
                println!();
            }
            "cursor" => {
                println!("    Cursor (Settings > Models > Override OpenAI Base URL):");
                println!("      http://localhost:13456/v1  (BYOK mode only)");
                println!();
            }
            _ => {}
        }
    }

    println!("  Not proxyable:");
    println!("    - GitHub Copilot (hardcoded endpoint)");
    println!("    - Gemini CLI (incompatible API format)");
}

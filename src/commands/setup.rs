//! Interactive first-run setup wizard.
//!
//! Collects all choices upfront, displays a recap for confirmation,
//! then writes config atomically in a single pass.

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

/// Auth capabilities per provider.
const PROVIDER_AUTH: &[(&str, bool, &str, &str)] = &[
    // (name, supports_oauth, oauth_id, env_var)
    ("anthropic", true, "anthropic-max", "ANTHROPIC_API_KEY"),
    ("openai", true, "openai-codex", "OPENAI_API_KEY"),
    ("gemini", true, "gemini", "GEMINI_API_KEY"),
    ("openrouter", false, "", "OPENROUTER_API_KEY"),
    ("deepseek", false, "", "DEEPSEEK_API_KEY"),
    ("mistral", false, "", "MISTRAL_API_KEY"),
];

fn auth_for(name: &str) -> Option<(bool, &'static str, &'static str)> {
    PROVIDER_AUTH
        .iter()
        .find(|(n, ..)| *n == name)
        .map(|(_, oauth, id, env)| (*oauth, *id, *env))
}

/// Overrides collected from the auth screen.
struct AuthOverride {
    provider: String,
    use_oauth: bool,
    oauth_id: String,
    entered_key: Option<String>,
    env_var: String,
}

/// All wizard choices, collected before any disk write.
struct Choices {
    tools: Vec<usize>,
    preset: String,
    preset_desc: String,
    auth: Vec<AuthOverride>,
    fallback: FallbackChoice,
    fallback_key: Option<String>,
    compliance: Compliance,
    budget: Option<BudgetChoice>,
}

/// Monthly budget cap chosen by the user.
///
/// `currency` is cosmetic only : the config schema stores the numeric value
/// in `[budget] monthly_limit_usd` regardless of the currency label. Grob
/// does no forex conversion.
#[derive(Clone)]
struct BudgetChoice {
    amount: i64,
    currency: &'static str,
}

/// Fallback provider chosen in the wizard.
///
/// Always prompted (even when a preset ships a fallback) so the user can
/// explicitly opt out and avoid the phantom `$OPENROUTER_API_KEY not set`
/// warning at startup. See `src/commands/setup.rs::screen_fallback`.
#[derive(Clone)]
enum FallbackChoice {
    /// No fallback provider. Any preset-shipped fallback provider and
    /// related model mappings are stripped from the written config.
    None,
    /// OpenRouter (the common default, reads `$OPENROUTER_API_KEY`).
    OpenRouter,
    /// Gemini OAuth/API key as fallback.
    Gemini,
    /// Keep whatever fallback the preset defines (expert mode).
    KeepPreset,
}

#[derive(Clone, Copy)]
enum Compliance {
    Standard,
    Dlp,
    EuGdpr,
    Enterprise,
    LocalOnly,
}

/// Flags from CLI arguments.
pub struct SetupFlags {
    /// Accepts all defaults without interactive prompts.
    pub yes: bool,
    /// Previews changes without writing to disk.
    pub dry_run: bool,
}

// ── Input helpers ──

fn read_line() -> String {
    let mut s = String::new();
    io::stdin().read_line(&mut s).ok();
    s.trim().to_string()
}

fn prompt_choice(max: usize) -> usize {
    loop {
        print!("  > ");
        io::stdout().flush().ok();
        if let Ok(n) = read_line().parse::<usize>() {
            if n >= 1 && n <= max {
                return n;
            }
        }
        println!("  Enter a number between 1 and {}", max);
    }
}

fn prompt_multi(max: usize) -> Vec<usize> {
    loop {
        print!("  > ");
        io::stdout().flush().ok();
        let input = read_line();
        if input.eq_ignore_ascii_case("all") {
            return (0..max).collect();
        }
        let v: Vec<usize> = input
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter_map(|s| s.trim().parse::<usize>().ok())
            .filter(|&n| n >= 1 && n <= max)
            .map(|n| n - 1)
            .collect();
        if !v.is_empty() {
            return v;
        }
        println!("  Enter numbers separated by commas (e.g. 1,3) or 'all'");
    }
}

fn prompt_key(env_var: &str) -> Option<String> {
    if std::env::var(env_var).is_ok() {
        println!("    ${} already set in environment", env_var);
        return None;
    }
    print!("    API key: ");
    io::stdout().flush().ok();
    let key = read_line();
    if key.is_empty() {
        println!("    Skipped");
        None
    } else {
        println!("    Accepted (stored as ${} reference)", env_var);
        Some(key)
    }
}

fn confirm(prompt: &str) -> bool {
    print!("{}", prompt);
    io::stdout().flush().ok();
    let a = read_line();
    a.eq_ignore_ascii_case("y") || a.eq_ignore_ascii_case("yes")
}

// ── Screens: collect only, no disk writes ──

fn screen_tools() -> Option<(Vec<usize>, String, String)> {
    println!("Which tools will you route through Grob?");
    println!("  (enter numbers separated by commas, e.g. 1,3)");
    println!();
    for (i, t) in TOOLS.iter().enumerate() {
        println!("  [{}] {:<16} {} {}", i + 1, t.name, t.tag, t.endpoint);
    }
    println!();
    println!("  [{}] Custom setup (manual)", TOOLS.len() + 1);
    println!();

    let sel = prompt_multi(TOOLS.len() + 1);
    if sel.contains(&TOOLS.len()) {
        return None;
    }

    let tools: Vec<&ToolInfo> = sel.iter().filter_map(|&i| TOOLS.get(i)).collect();
    if tools.is_empty() {
        return None;
    }

    let (preset, desc) = match (
        tools.iter().any(|t| t.needs_anthropic),
        tools.iter().any(|t| t.needs_openai),
    ) {
        (true, true) | (false, true) => ("fast", "Anthropic + OpenAI + Gemini + OpenRouter"),
        _ => ("perf", "Anthropic OAuth + OpenRouter fallback"),
    };

    let names: Vec<&str> = tools.iter().map(|t| t.name).collect();
    println!();
    println!("Setting up for {}...", names.join(" + "));
    println!("  Preset: {} ({})", preset, desc);

    Some((sel, preset.to_string(), desc.to_string()))
}

fn screen_auth(providers: &[String]) -> Vec<AuthOverride> {
    if providers.is_empty() {
        return vec![];
    }

    println!();
    println!("  Provider authentication:");
    println!();

    let mut out = Vec::new();
    for name in providers {
        let (supports_oauth, oauth_id, env_var) = match auth_for(name) {
            Some(v) => v,
            None => continue,
        };

        println!("  {}:", name);
        if supports_oauth {
            println!("    [1] OAuth (subscription, recommended)");
            println!("    [2] API key (${})", env_var);
            let choice = prompt_choice(2);
            if choice == 1 {
                out.push(AuthOverride {
                    provider: name.clone(),
                    use_oauth: true,
                    oauth_id: oauth_id.to_string(),
                    entered_key: None,
                    env_var: env_var.to_string(),
                });
                println!("    OAuth — will prompt on first `grob start`");
            } else {
                let key = prompt_key(env_var);
                out.push(AuthOverride {
                    provider: name.clone(),
                    use_oauth: false,
                    oauth_id: String::new(),
                    entered_key: key,
                    env_var: env_var.to_string(),
                });
            }
        } else {
            println!("    [1] Enter API key now");
            println!("    [2] I'll set ${} later", env_var);
            if prompt_choice(2) == 1 {
                let key = prompt_key(env_var);
                out.push(AuthOverride {
                    provider: name.clone(),
                    use_oauth: false,
                    oauth_id: String::new(),
                    entered_key: key,
                    env_var: env_var.to_string(),
                });
            } else {
                println!("    OK — set ${} before running grob", env_var);
            }
        }
        println!();
    }
    out
}

fn screen_fallback(preset_has_fallback: bool) -> (FallbackChoice, Option<String>) {
    println!();
    println!("  Fallback provider?");
    println!("    [1] Aucun (no fallback)");
    println!("    [2] OpenRouter (recommended — 100+ models)");
    println!("    [3] Gemini ($GEMINI_API_KEY)");
    if preset_has_fallback {
        println!("    [4] Custom (keep the fallback shipped by the preset)");
    } else {
        println!("    [4] Custom (keep what the preset defines, if anything)");
    }
    match prompt_choice(4) {
        1 => (FallbackChoice::None, None),
        2 => (FallbackChoice::OpenRouter, prompt_key("OPENROUTER_API_KEY")),
        3 => (FallbackChoice::Gemini, prompt_key("GEMINI_API_KEY")),
        _ => (FallbackChoice::KeepPreset, None),
    }
}

fn screen_compliance(tools: &[&ToolInfo]) -> Compliance {
    println!();
    println!("  Security & compliance:");
    println!("    [1] Standard (default — no restrictions)");
    println!("    [2] DLP (secret scanning + PII detection)");
    println!("    [3] EU/GDPR + EU AI Act (EU-only + DLP + transparency)");
    println!("    [4] Enterprise (audit + DLP + rate limiting + OWASP)");
    println!("    [5] Local-only (Ollama — zero data transfer)");

    let choice = prompt_choice(5);
    match choice {
        2 => Compliance::Dlp,
        3 => {
            let warnings = gdpr_warnings(tools);
            if !warnings.is_empty() {
                println!();
                println!("  GDPR compatibility notes:");
                for w in &warnings {
                    println!("    {}", w);
                }
                println!();
                if !confirm("  Continue anyway? [y/N] ") {
                    println!("    Falling back to Standard");
                    return Compliance::Standard;
                }
            }
            Compliance::EuGdpr
        }
        4 => Compliance::Enterprise,
        5 => Compliance::LocalOnly,
        _ => Compliance::Standard,
    }
}

fn screen_budget() -> Option<BudgetChoice> {
    println!();
    println!("  Monthly budget cap:");
    println!("    [1] Illimite");
    println!("    [2] Saisir un montant");

    match prompt_choice(2) {
        2 => {
            print!("    Montant: ");
            io::stdout().flush().ok();
            let amount = read_line().parse::<i64>().ok()?;
            print!("    Devise [USD]: ");
            io::stdout().flush().ok();
            let currency_input = read_line();
            let currency = parse_currency(&currency_input);
            Some(BudgetChoice { amount, currency })
        }
        _ => None,
    }
}

/// Parses a free-form currency input, defaulting to USD when empty or invalid.
///
/// Accepted values : `USD`, `EUR`, `GBP` (case-insensitive). The config schema
/// only stores amounts in USD, so non-USD values are still displayed in the
/// recap for transparency but the persisted value goes into
/// `[budget] monthly_limit_usd` unchanged.
fn parse_currency(input: &str) -> &'static str {
    match input.trim().to_ascii_uppercase().as_str() {
        "" | "USD" => "USD",
        "EUR" => "EUR",
        "GBP" => "GBP",
        _ => "USD",
    }
}

fn gdpr_warnings(tools: &[&ToolInfo]) -> Vec<String> {
    tools
        .iter()
        .filter_map(|t| match t.name {
            "Claude Code" | "Forge" => Some(format!(
                "{}: Anthropic does not guarantee EU-only processing.",
                t.name
            )),
            "Codex CLI" => Some(format!(
                "{}: OpenAI EU residency — verify your project is set to EU region.",
                t.name
            )),
            _ => None,
        })
        .collect()
}

// ── Recap ──

fn display_recap(c: &Choices, path: &Path, dry_run: bool, auto_confirm: bool) -> bool {
    println!();
    println!("  ┌──────────────────────────────────────────┐");
    println!("  │          Configuration summary            │");
    println!("  └──────────────────────────────────────────┘");
    println!();

    let names: Vec<&str> = c
        .tools
        .iter()
        .filter_map(|&i| TOOLS.get(i).map(|t| t.name))
        .collect();
    println!(
        "    Tools:       {}",
        if names.is_empty() {
            "(custom)".to_string()
        } else {
            names.join(", ")
        }
    );
    println!("    Preset:      {} ({})", c.preset, c.preset_desc);

    println!("    Providers:");
    for a in &c.auth {
        if a.use_oauth {
            println!("      {:<14} OAuth ({})", a.provider, a.oauth_id);
        } else {
            println!("      {:<14} ${}", a.provider, a.env_var);
        }
    }
    match c.fallback {
        FallbackChoice::None => {
            println!("      (no fallback provider)");
        }
        FallbackChoice::OpenRouter => {
            println!("      {:<14} $OPENROUTER_API_KEY (fallback)", "openrouter");
        }
        FallbackChoice::Gemini => {
            println!("      {:<14} $GEMINI_API_KEY (fallback)", "gemini");
        }
        FallbackChoice::KeepPreset => {
            println!("      (fallback: keep preset default)");
        }
    }

    let label = match c.compliance {
        Compliance::Standard => "Standard",
        Compliance::Dlp => "DLP",
        Compliance::EuGdpr => "EU/GDPR + EU AI Act",
        Compliance::Enterprise => "Enterprise",
        Compliance::LocalOnly => "Local-only (Ollama)",
    };
    println!("    Compliance:  {}", label);

    match &c.budget {
        Some(b) => println!(
            "    Budget:      {} {}/month (warn at 80%)",
            b.amount, b.currency
        ),
        None => println!("    Budget:      unlimited"),
    }

    println!();
    println!("    Config:      {}", path.display());

    if dry_run {
        println!();
        println!("  Dry run — no changes written.");
        return false;
    }

    if auto_confirm {
        return true;
    }

    println!();
    confirm("  Write configuration? [y/N] ")
}

fn print_exports(c: &Choices) {
    let fallback_env = match c.fallback {
        FallbackChoice::OpenRouter => Some("OPENROUTER_API_KEY"),
        FallbackChoice::Gemini => Some("GEMINI_API_KEY"),
        FallbackChoice::None | FallbackChoice::KeepPreset => None,
    };
    let keys: Vec<(&str, &str)> = c
        .auth
        .iter()
        .filter_map(|a| a.entered_key.as_deref().map(|k| (a.env_var.as_str(), k)))
        .chain(fallback_env.zip(c.fallback_key.as_deref()))
        .collect();
    if keys.is_empty() {
        return;
    }
    println!();
    println!("  Add to your shell profile:");
    for (var, key) in keys {
        println!("    export {}={}", var, key);
    }
}

// ── Atomic write ──

/// Removes fallback providers (by name) from a loaded preset config and
/// drops any `[[models.mappings]]` that still reference them.
///
/// Invoked when the user picks `FallbackChoice::None` so the written config
/// does not carry a dead `$OPENROUTER_API_KEY` reference that would warn at
/// startup. Kept as a free function for direct snapshot testing.
pub(crate) fn strip_fallback(config: &mut toml::Value, names_to_strip: &[&str]) {
    if let Some(providers) = config.get_mut("providers").and_then(|p| p.as_array_mut()) {
        providers.retain(|p| {
            let keep = p
                .get("name")
                .and_then(|n| n.as_str())
                .is_none_or(|n| !names_to_strip.contains(&n));
            keep
        });
    }
    if let Some(models) = config.get_mut("models").and_then(|m| m.as_array_mut()) {
        for model in models.iter_mut() {
            let Some(mappings) = model.get_mut("mappings").and_then(|m| m.as_array_mut()) else {
                continue;
            };
            mappings.retain(|m| {
                m.get("provider")
                    .and_then(|p| p.as_str())
                    .is_none_or(|p| !names_to_strip.contains(&p))
            });
        }
    }
}

fn patch(config: &mut toml::Value, section: &str, fields: &[(&str, toml::Value)]) {
    let table = config
        .as_table_mut()
        .unwrap()
        .entry(section)
        .or_insert_with(|| toml::Value::Table(Default::default()))
        .as_table_mut()
        .unwrap();
    for (k, v) in fields {
        table.insert(k.to_string(), v.clone());
    }
}

fn write_config(choices: &Choices, path: &Path) -> Result<()> {
    // Backup
    if path.exists() {
        let backup = path.with_extension("toml.backup");
        std::fs::copy(path, &backup)?;
        println!("  Backup: {}", backup.display());
    }

    // For local-only, swap the entire preset
    let preset = if matches!(choices.compliance, Compliance::LocalOnly) {
        "local"
    } else {
        &choices.preset
    };
    crate::preset::apply_preset(preset, path)?;

    // Read back and apply all overrides in memory
    let content = std::fs::read_to_string(path)?;
    let mut config: toml::Value = toml::from_str(&content)?;

    // Auth overrides
    if let Some(providers) = config.get_mut("providers").and_then(|p| p.as_array_mut()) {
        for p in providers.iter_mut() {
            let pname = p.get("name").and_then(|n| n.as_str()).unwrap_or("");
            let Some(ov) = choices.auth.iter().find(|a| a.provider == pname) else {
                continue;
            };
            let t = p.as_table_mut().unwrap();
            if ov.use_oauth {
                t.insert("auth_type".into(), "oauth".into());
                t.insert(
                    "oauth_provider".into(),
                    toml::Value::String(ov.oauth_id.clone()),
                );
                t.remove("api_key");
            } else {
                t.insert("auth_type".into(), "apikey".into());
                t.insert(
                    "api_key".into(),
                    toml::Value::String(format!("${}", ov.env_var)),
                );
                t.remove("oauth_provider");
            }
        }
    }

    // Fallback
    match choices.fallback {
        FallbackChoice::None => {
            // Strip any fallback provider shipped by the preset plus the model
            // mapping references that point to it — otherwise the config
            // resolver warns at startup on `$OPENROUTER_API_KEY not set` even
            // though the user explicitly said "no fallback".
            strip_fallback(&mut config, &["openrouter", "gemini"]);
        }
        FallbackChoice::OpenRouter => {
            if let Some(providers) = config.get_mut("providers").and_then(|p| p.as_array_mut()) {
                providers.retain(|p| p.get("name").and_then(|n| n.as_str()) != Some("openrouter"));
                let mut t = toml::map::Map::new();
                t.insert("name".into(), "openrouter".into());
                t.insert("provider_type".into(), "openrouter".into());
                t.insert("pass_through".into(), toml::Value::Boolean(true));
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("models".into(), toml::Value::Array(vec![]));
                t.insert("api_key".into(), "$OPENROUTER_API_KEY".into());
                providers.push(toml::Value::Table(t));
            }
        }
        FallbackChoice::Gemini => {
            if let Some(providers) = config.get_mut("providers").and_then(|p| p.as_array_mut()) {
                providers.retain(|p| p.get("name").and_then(|n| n.as_str()) != Some("gemini"));
                let mut t = toml::map::Map::new();
                t.insert("name".into(), "gemini".into());
                t.insert("provider_type".into(), "gemini".into());
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("models".into(), toml::Value::Array(vec![]));
                t.insert("api_key".into(), "$GEMINI_API_KEY".into());
                providers.push(toml::Value::Table(t));
            }
        }
        FallbackChoice::KeepPreset => {
            // Leave the preset as-is.
        }
    }

    // Compliance patches
    match choices.compliance {
        Compliance::Standard => {}
        Compliance::Dlp => {
            patch(&mut config, "dlp", &[("enabled", true.into())]);
        }
        Compliance::Enterprise => {
            patch(
                &mut config,
                "security",
                &[
                    ("enabled", true.into()),
                    ("audit_dir", "~/.grob/audit".into()),
                    ("rate_limit_rps", 100.into()),
                    ("rate_limit_burst", 200.into()),
                    ("circuit_breaker", true.into()),
                    ("security_headers", true.into()),
                ],
            );
            patch(&mut config, "dlp", &[("enabled", true.into())]);
        }
        Compliance::LocalOnly => {
            patch(&mut config, "security", &[("enabled", true.into())]);
            patch(&mut config, "dlp", &[("enabled", true.into())]);
        }
        Compliance::EuGdpr => {
            // Write first, then overlay compliance preset (reads from disk)
            std::fs::write(path, toml::to_string_pretty(&config)?)?;
            crate::preset::overlay_compliance("eu-ai-act", path)?;
            return Ok(());
        }
    }

    // Budget
    if let Some(ref b) = choices.budget {
        patch(
            &mut config,
            "budget",
            &[
                ("monthly_limit_usd", b.amount.into()),
                ("warn_at_percent", 80.into()),
            ],
        );
    }

    std::fs::write(path, toml::to_string_pretty(&config)?)?;
    Ok(())
}

// ── Provider list from preset TOML ──

fn providers_from_preset(name: &str) -> Vec<String> {
    let content = match crate::preset::preset_content(name) {
        Ok(c) => c,
        Err(_) => return vec![],
    };
    let val: toml::Value = match toml::from_str(&content) {
        Ok(v) => v,
        Err(_) => return vec![],
    };
    val.get("providers")
        .and_then(|p| p.as_array())
        .map(|arr| {
            arr.iter()
                .filter(|p| p.get("enabled").and_then(|e| e.as_bool()).unwrap_or(true))
                .filter_map(|p| p.get("name").and_then(|n| n.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

// ── Main entry point ──

/// Runs the interactive setup wizard.
///
/// Returns `true` if config was written, `false` if cancelled or dry-run.
///
/// # Errors
///
/// Returns an error if config writing fails or the backup copy fails.
pub async fn run_setup_wizard(config_path: &Path, flags: &SetupFlags) -> Result<bool> {
    println!();

    // Detect existing config
    if config_path.exists() && !flags.yes {
        println!("Configuration detected: {}", config_path.display());
        println!();
        println!("  [1] Edit (re-run wizard, keeping backup)");
        println!("  [2] Replace from scratch");
        println!("  [3] Cancel");
        if prompt_choice(3) == 3 {
            return Ok(false);
        }
        println!();
    } else if !config_path.exists() {
        println!("Welcome to Grob! No configuration detected.");
        println!();
    }

    // --yes: defaults, no prompts
    if flags.yes {
        let choices = Choices {
            tools: (0..TOOLS.len()).collect(),
            preset: "perf".into(),
            preset_desc: "Anthropic OAuth + OpenRouter fallback".into(),
            auth: vec![AuthOverride {
                provider: "anthropic".into(),
                use_oauth: true,
                oauth_id: "anthropic-max".into(),
                entered_key: None,
                env_var: "ANTHROPIC_API_KEY".into(),
            }],
            // `--yes` stays conservative : no fallback provider, so we never
            // emit a phantom "$OPENROUTER_API_KEY not set" warning on a cold
            // install without a subscription.
            fallback: FallbackChoice::None,
            fallback_key: None,
            compliance: Compliance::Standard,
            budget: None,
        };
        display_recap(&choices, config_path, flags.dry_run, true);
        if flags.dry_run {
            return Ok(false);
        }
        write_config(&choices, config_path)?;
        println!();
        println!("  Config written to {}", config_path.display());
        chain_auto_flow(config_path, flags).await;
        print_status(config_path);
        return Ok(true);
    }

    // Screen 1: Tools
    let (tools, preset, preset_desc) = match screen_tools() {
        Some(t) => t,
        None => return setup_custom(config_path),
    };

    // Read providers from preset TOML (no hardcoded table)
    let providers = providers_from_preset(&preset);

    // Screen 2: Auth
    let auth = screen_auth(&providers);

    // Screen 3: Fallback — always prompted (opt-in). If the preset ships a
    // fallback (openrouter / gemini) and the user says "Aucun", we strip the
    // fallback provider from the written config so no phantom warning fires
    // at startup.
    let preset_has_fallback = providers.iter().any(|p| p == "openrouter" || p == "gemini");
    let (fallback, fallback_key) = screen_fallback(preset_has_fallback);

    // Screen 4: Compliance
    let tool_refs: Vec<&ToolInfo> = tools.iter().filter_map(|&i| TOOLS.get(i)).collect();
    let compliance = screen_compliance(&tool_refs);

    // Screen 5: Budget
    let budget = screen_budget();

    let choices = Choices {
        tools,
        preset,
        preset_desc,
        auth,
        fallback,
        fallback_key,
        compliance,
        budget,
    };

    // Screen 6: Recap
    if !display_recap(&choices, config_path, flags.dry_run, false) {
        if !flags.dry_run {
            println!("  Setup cancelled.");
        }
        return Ok(false);
    }

    // Write
    write_config(&choices, config_path)?;
    println!();
    println!("  Config written to {}", config_path.display());
    print_exports(&choices);
    chain_auto_flow(config_path, flags).await;
    print_status(config_path);
    print_usage(&choices);

    Ok(true)
}

/// Chains the auto-flow credential setup after the wizard writes the config.
///
/// Invoked from `run_setup_wizard` right after `write_config`. Reads the freshly
/// written config, detects missing credentials (OAuth tokens or API keys), and
/// runs the interactive setup from [`crate::auth::auto_flow`] so the user lands
/// ready-to-run without a second manual step. Silent no-op when `flags.yes` is
/// set (user explicitly skipped prompts), when stdin is not a TTY
/// (non-interactive installs, CI, tests), or when no provider needs setup.
async fn chain_auto_flow(config_path: &Path, flags: &SetupFlags) {
    if flags.yes || !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return;
    }
    let Ok(config) = crate::cli::AppConfig::from_file(config_path) else {
        return;
    };
    let Ok(store) = crate::storage::GrobStore::open(&crate::storage::GrobStore::default_path())
    else {
        return;
    };
    let store = std::sync::Arc::new(store);
    let Ok(token_store) = crate::auth::TokenStore::with_store(store) else {
        return;
    };
    let statuses = crate::auth::auto_flow::detect_credentials(&config.providers, &token_store);
    let has_missing = statuses
        .iter()
        .any(|s| !matches!(s, crate::auth::auto_flow::CredentialStatus::Ready));
    if !has_missing {
        return;
    }
    let _ = crate::auth::auto_flow::run_interactive_flow(statuses, &token_store).await;
}

fn print_status(config_path: &Path) {
    let statuses = match crate::preset::check_credentials(config_path) {
        Ok(s) => s,
        Err(_) => return,
    };
    println!();
    println!("  Provider status:");
    for s in &statuses {
        let auth = if s.detail.contains("OAuth") {
            "oauth"
        } else {
            "api_key"
        };
        let icon = if s.ok { "ok" } else { &s.detail };
        println!("    {} ({}) — {}", s.provider_name, auth, icon);
    }
    if statuses.iter().any(|s| !s.ok && s.detail.contains("OAuth")) {
        println!();
        println!("  To complete OAuth: grob start (auto-prompt) or grob connect");
    }
}

fn setup_custom(config_path: &Path) -> Result<bool> {
    println!();
    println!("Creating default config...");
    if let Some(p) = config_path.parent() {
        std::fs::create_dir_all(p)?;
    }
    std::fs::write(
        config_path,
        concat!(
            "# Grob configuration\n",
            "# grob preset list          — see presets\n",
            "# grob preset apply perf    — apply one\n\n",
            "[server]\nport = 13456\n\n[router]\ndefault = \"default\"\n",
        ),
    )?;
    println!("  Config written to {}", config_path.display());
    println!();
    println!("  Next: grob preset apply perf && grob connect && grob start -d");
    Ok(true)
}

fn print_usage(choices: &Choices) {
    println!();
    println!("  How to use:");
    println!();
    for &i in &choices.tools {
        let Some(t) = TOOLS.get(i) else { continue };
        match t.name {
            "Claude Code" => println!("    Claude Code:   grob exec -- claude"),
            "Codex CLI" => println!("    Codex CLI:     grob exec -- codex"),
            "Forge" => println!("    Forge:         grob exec -- forge"),
            "Aider" => println!("    Aider:         grob exec -- aider"),
            "Continue.dev" => println!("    Continue.dev:  apiBase: http://localhost:13456"),
            "Cursor" => println!("    Cursor:        Override Base URL: http://localhost:13456/v1"),
            _ => {}
        }
    }
    println!();
    println!("  Not proxyable (hardcoded endpoints): GitHub Copilot, Gemini CLI");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// W-2 : quand l'utilisateur choisit `Aucun` dans le nouveau screen
    /// fallback, `strip_fallback` retire le provider openrouter du preset
    /// charge ET les `[[models.mappings]]` qui le referencent. Sans ce
    /// nettoyage, un warning fantome `$OPENROUTER_API_KEY not set` tombe au
    /// prochain demarrage meme si l'utilisateur a dit non au fallback.
    #[test]
    fn test_w2_strip_fallback_removes_openrouter_and_mappings() {
        let preset = crate::preset::preset_content("perf").expect("perf preset loads");
        let mut config: toml::Value = toml::from_str(&preset).expect("perf preset parses");

        // Sanity avant strip : openrouter doit bien etre present.
        let providers_before = config
            .get("providers")
            .and_then(|p| p.as_array())
            .unwrap()
            .len();
        assert!(
            providers_before >= 2,
            "perf preset should ship openrouter alongside anthropic"
        );

        strip_fallback(&mut config, &["openrouter", "gemini"]);

        // Apres strip : plus d'openrouter nulle part.
        let providers = config
            .get("providers")
            .and_then(|p| p.as_array())
            .expect("providers still an array");
        for p in providers {
            let name = p.get("name").and_then(|n| n.as_str()).unwrap_or("");
            assert_ne!(name, "openrouter", "openrouter provider must be removed");
            assert_ne!(name, "gemini", "gemini provider must be removed");
        }

        // Plus aucune mapping ne reference openrouter.
        let models = config
            .get("models")
            .and_then(|m| m.as_array())
            .expect("models still an array");
        for m in models {
            if let Some(mappings) = m.get("mappings").and_then(|x| x.as_array()) {
                for mp in mappings {
                    let prov = mp.get("provider").and_then(|p| p.as_str()).unwrap_or("");
                    assert_ne!(
                        prov,
                        "openrouter",
                        "openrouter mapping must be stripped from model {:?}",
                        m.get("name")
                    );
                    assert_ne!(prov, "gemini", "gemini mapping must be stripped");
                }
            }
        }

        // Snapshot du resultat serialise pour capter toute regression.
        let rendered = toml::to_string_pretty(&config).expect("serialize back");
        insta::assert_snapshot!("w2_perf_preset_without_fallback", rendered);
    }

    /// W-3 : `parse_currency` reconnait USD/EUR/GBP, ignore la casse, et
    /// tombe sur USD quand l'entree est vide ou inconnue. Ce helper est le
    /// seul morceau pur du nouveau screen_budget libre, donc c'est le bon
    /// endroit pour le verrouiller.
    #[test]
    fn test_w3_parse_currency_defaults_and_variants() {
        assert_eq!(parse_currency(""), "USD");
        assert_eq!(parse_currency("usd"), "USD");
        assert_eq!(parse_currency("USD"), "USD");
        assert_eq!(parse_currency("  eur "), "EUR");
        assert_eq!(parse_currency("GBP"), "GBP");
        assert_eq!(parse_currency("bitcoin"), "USD");
    }

    /// W-3 : le patch TOML applique par `write_config` pour un budget custom
    /// s'ecrit sous `[budget] monthly_limit_usd` + `warn_at_percent = 80`.
    /// Verrouille le schema pour que le MCP server (qui lit cette cle) ne
    /// casse pas sur un futur refactor.
    #[test]
    fn test_w3_budget_patch_writes_monthly_limit_usd() {
        let mut config: toml::Value = toml::from_str("").unwrap();
        let budget = BudgetChoice {
            amount: 123,
            currency: "EUR",
        };
        patch(
            &mut config,
            "budget",
            &[
                ("monthly_limit_usd", budget.amount.into()),
                ("warn_at_percent", 80.into()),
            ],
        );
        let section = config.get("budget").and_then(|v| v.as_table()).unwrap();
        assert_eq!(
            section
                .get("monthly_limit_usd")
                .and_then(|v| v.as_integer()),
            Some(123)
        );
        assert_eq!(
            section.get("warn_at_percent").and_then(|v| v.as_integer()),
            Some(80)
        );
    }

    /// W-2 : strip sur un config qui n'a pas de provider a retirer = no-op.
    #[test]
    fn test_w2_strip_fallback_noop_when_absent() {
        let mut config: toml::Value = toml::from_str(
            r#"
[[providers]]
name = "anthropic"
provider_type = "anthropic"
enabled = true

[[models]]
name = "default"

[[models.mappings]]
provider = "anthropic"
actual_model = "claude-sonnet-4-6"
priority = 1
"#,
        )
        .unwrap();

        strip_fallback(&mut config, &["openrouter", "gemini"]);

        let providers_after = config.get("providers").and_then(|p| p.as_array()).unwrap();
        assert_eq!(providers_after.len(), 1);
        let mappings_after = config
            .get("models")
            .and_then(|m| m.as_array())
            .unwrap()
            .iter()
            .filter_map(|m| m.get("mappings").and_then(|x| x.as_array()))
            .next()
            .unwrap();
        assert_eq!(mappings_after.len(), 1);
    }
}

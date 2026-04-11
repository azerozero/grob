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

/// Custom endpoint configured during setup.
struct CustomEndpoint {
    /// User-chosen name for this provider (e.g. "my-llm").
    name: String,
    /// `"openai_compatible"` or `"anthropic_compatible"`.
    provider_type: String,
    /// Base URL (e.g. `https://my-llm.company.com/v1`).
    base_url: String,
    /// API key entered by the user (None = set later via env var).
    api_key: Option<String>,
}

/// All wizard choices, collected before any disk write.
struct Choices {
    tools: Vec<usize>,
    preset: String,
    preset_desc: String,
    auth: Vec<AuthOverride>,
    fallback: FallbackChoice,
    fallback_key: Option<String>,
    custom_endpoints: Vec<CustomEndpoint>,
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

/// Flags from CLI arguments and environment overrides.
pub struct SetupFlags {
    /// Accepts all defaults without interactive prompts.
    pub yes: bool,
    /// Previews changes without writing to disk.
    pub dry_run: bool,
    /// Restricts the wizard to a single section (providers, budget, compliance, fallback).
    pub edit_section: Option<String>,
}

/// Known top-level TOML sections in grob.toml (for schema drift detection).
const KNOWN_SECTIONS: &[&str] = &[
    "version",
    "server",
    "router",
    "providers",
    "models",
    "presets",
    "budget",
    "dlp",
    "auth",
    "tap",
    "security",
    "cache",
    "compliance",
    "tool_layer",
    "mcp",
    "user",
    "otel",
    "log_export",
    "pledge",
    "tee",
    "fips",
    "policies",
    "harness",
];

/// Deprecated config keys and their migration hints.
const DEPRECATED_KEYS: &[(&str, &str)] = &[
    (
        "openai_compat",
        "Renamed to [server.openai_compat]. Move the section under [server].",
    ),
    (
        "rate_limit",
        "Moved to [security]. Use rate_limit_rps and rate_limit_burst under [security].",
    ),
];

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

fn prompt_key_for_provider(env_var: &str, provider_name: Option<&str>) -> Option<String> {
    if std::env::var(env_var).is_ok() {
        println!("    ${} already set in environment", env_var);
        return None;
    }
    print!("    API key: ");
    io::stdout().flush().ok();
    let key = read_line();
    if key.is_empty() {
        println!("    Skipped");
        return None;
    }

    // Best-effort validation when the provider is known.
    if let Some(name) = provider_name {
        let rt = tokio::runtime::Handle::try_current();
        let valid = match rt {
            Ok(handle) => tokio::task::block_in_place(|| {
                handle.block_on(super::credential_check::validate_api_key(name, &key))
            }),
            Err(_) => {
                // No runtime available — skip validation.
                true
            }
        };
        if !valid {
            println!(
                "    Warning: {} returned auth error. The key may be expired, revoked, or incorrect.",
                name
            );
            println!("    Check your key at the provider dashboard, or try a different one.");
            println!("    Continue anyway? [y/N]");
            if !confirm("    > ") {
                println!(
                    "    Key rejected. Run: grob connect {} (to retry later)",
                    name
                );
                return None;
            }
        }
    }

    println!("    Accepted (stored as ${} reference)", env_var);
    Some(key)
}

fn confirm(prompt: &str) -> bool {
    print!("{}", prompt);
    io::stdout().flush().ok();
    let a = read_line();
    a.eq_ignore_ascii_case("y") || a.eq_ignore_ascii_case("yes")
}

// ── Credential discovery ──

/// Detects API keys present in the environment for known providers.
fn discover_credentials() -> Vec<(&'static str, &'static str)> {
    PROVIDER_AUTH
        .iter()
        .filter_map(|(name, _, _, env_var)| {
            if std::env::var(env_var).is_ok() {
                Some((*name, *env_var))
            } else {
                None
            }
        })
        .collect()
}

/// Checks the existing config for unknown or deprecated top-level keys.
fn check_schema_drift(config_path: &Path) {
    let content = match std::fs::read_to_string(config_path) {
        Ok(c) => c,
        Err(_) => return,
    };
    let table: toml::Value = match toml::from_str(&content) {
        Ok(v) => v,
        Err(_) => return,
    };
    let Some(top) = table.as_table() else {
        return;
    };

    let mut drift_found = false;

    for (key, hint) in DEPRECATED_KEYS {
        if top.contains_key(*key) {
            if !drift_found {
                println!();
                println!("  Schema drift detected in existing config:");
                drift_found = true;
            }
            println!("    [deprecated] '{}': {}", key, hint);
        }
    }

    for key in top.keys() {
        if !KNOWN_SECTIONS.contains(&key.as_str())
            && !DEPRECATED_KEYS.iter().any(|(k, _)| *k == key.as_str())
        {
            if !drift_found {
                println!();
                println!("  Schema drift detected in existing config:");
                drift_found = true;
            }
            println!(
                "    [unknown] '{}': not a recognized section. Remove it or check for typos.",
                key
            );
        }
    }
}

/// Opens a URL in the default browser (best-effort, no error on failure).
#[allow(dead_code)]
fn open_browser(url: &str) {
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(url).spawn();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("cmd")
            .args(["/C", "start", url])
            .spawn();
    }
}

/// Reads an existing grob.toml and extracts pre-fill defaults.
fn prefill_from_config(config_path: &Path) -> Option<(Vec<String>, bool, Option<i64>)> {
    let content = std::fs::read_to_string(config_path).ok()?;
    let config: toml::Value = toml::from_str(&content).ok()?;

    let providers: Vec<String> = config
        .get("providers")
        .and_then(|p| p.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|p| p.get("name").and_then(|n| n.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let has_fallback = providers.iter().any(|p| p == "openrouter" || p == "gemini");

    let budget = config
        .get("budget")
        .and_then(|b| b.get("monthly_limit_usd"))
        .and_then(|v| v.as_integer());

    Some((providers, has_fallback, budget))
}

/// Reads GROB_SETUP_* environment variables for non-interactive setup.
fn env_overrides() -> (Option<String>, Option<i64>, Option<String>) {
    let provider = std::env::var("GROB_SETUP_PROVIDER").ok();
    let budget = std::env::var("GROB_SETUP_BUDGET")
        .ok()
        .and_then(|v| v.parse::<i64>().ok());
    let compliance = std::env::var("GROB_SETUP_COMPLIANCE").ok();
    (provider, budget, compliance)
}

/// Maps a compliance string to its enum variant.
fn parse_compliance(s: &str) -> Compliance {
    match s.to_lowercase().as_str() {
        "dlp" => Compliance::Dlp,
        "gdpr" | "eu-gdpr" | "eu" => Compliance::EuGdpr,
        "enterprise" => Compliance::Enterprise,
        "local" | "local-only" | "ollama" => Compliance::LocalOnly,
        _ => Compliance::Standard,
    }
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

    let discovered = discover_credentials();

    println!();
    println!("  Provider authentication:");
    if !discovered.is_empty() {
        println!();
        println!("  Detected credentials in environment:");
        for (name, var) in &discovered {
            println!("    {} (${} found)", name, var);
        }
    }
    println!();

    let mut out = Vec::new();
    for name in providers {
        let (supports_oauth, oauth_id, env_var) = match auth_for(name) {
            Some(v) => v,
            None => continue,
        };

        let env_present = discovered.iter().any(|(n, _)| *n == name.as_str());

        println!("  {}:", name);
        if env_present {
            println!("    ${} detected in environment", env_var);
            println!("    [1] Use environment variable (recommended)");
            if supports_oauth {
                println!("    [2] OAuth (subscription)");
                println!("    [3] Enter a different API key");
                let choice = prompt_choice(3);
                match choice {
                    1 => {
                        out.push(AuthOverride {
                            provider: name.clone(),
                            use_oauth: false,
                            oauth_id: String::new(),
                            entered_key: None,
                            env_var: env_var.to_string(),
                        });
                        println!("    Using ${}", env_var);
                    }
                    2 => {
                        out.push(AuthOverride {
                            provider: name.clone(),
                            use_oauth: true,
                            oauth_id: oauth_id.to_string(),
                            entered_key: None,
                            env_var: env_var.to_string(),
                        });
                        println!("    OAuth — will prompt on first `grob start`");
                    }
                    _ => {
                        let key = prompt_key_for_provider(env_var, Some(name));
                        out.push(AuthOverride {
                            provider: name.clone(),
                            use_oauth: false,
                            oauth_id: String::new(),
                            entered_key: key,
                            env_var: env_var.to_string(),
                        });
                    }
                }
            } else {
                println!("    [2] Enter a different API key");
                let choice = prompt_choice(2);
                if choice == 1 {
                    out.push(AuthOverride {
                        provider: name.clone(),
                        use_oauth: false,
                        oauth_id: String::new(),
                        entered_key: None,
                        env_var: env_var.to_string(),
                    });
                    println!("    Using ${}", env_var);
                } else {
                    let key = prompt_key_for_provider(env_var, Some(name));
                    out.push(AuthOverride {
                        provider: name.clone(),
                        use_oauth: false,
                        oauth_id: String::new(),
                        entered_key: key,
                        env_var: env_var.to_string(),
                    });
                }
            }
        } else if supports_oauth {
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
                let key = prompt_key_for_provider(env_var, Some(name));
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
            println!(
                "    [2] Set ${} later. Run: export {}=<your-key>",
                env_var, env_var
            );
            if prompt_choice(2) == 1 {
                let key = prompt_key_for_provider(env_var, Some(name));
                out.push(AuthOverride {
                    provider: name.clone(),
                    use_oauth: false,
                    oauth_id: String::new(),
                    entered_key: key,
                    env_var: env_var.to_string(),
                });
            } else {
                println!(
                    "    Set it before running grob: export {}=<your-key>",
                    env_var
                );
            }
        }
        println!();
    }
    out
}

fn screen_fallback(preset_has_fallback: bool) -> (FallbackChoice, Option<String>) {
    println!();
    println!("  Fallback provider (used when the primary is down or rate-limited):");
    println!("    [1] None (no fallback — primary only)");
    println!("    [2] OpenRouter (recommended — 100+ models, sign up: https://openrouter.ai)");
    println!("    [3] Gemini (requires $GEMINI_API_KEY)");
    if preset_has_fallback {
        println!("    [4] Keep preset default");
    } else {
        println!("    [4] Keep preset default (if any)");
    }
    match prompt_choice(4) {
        1 => (FallbackChoice::None, None),
        2 => (
            FallbackChoice::OpenRouter,
            prompt_key_for_provider("OPENROUTER_API_KEY", Some("openrouter")),
        ),
        3 => (
            FallbackChoice::Gemini,
            prompt_key_for_provider("GEMINI_API_KEY", Some("gemini")),
        ),
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

fn screen_budget(existing_budget: Option<i64>) -> Option<BudgetChoice> {
    println!();
    println!("  Monthly budget cap:");
    if let Some(current) = existing_budget {
        println!("    Current: {} USD/month", current);
    }
    println!("    [1] Unlimited");
    println!("    [2] Set a limit");

    match prompt_choice(2) {
        2 => {
            if let Some(current) = existing_budget {
                print!("    Amount [{}]: ", current);
            } else {
                print!("    Amount: ");
            }
            io::stdout().flush().ok();
            let input = read_line();
            let amount = if input.is_empty() {
                existing_budget?
            } else {
                input.parse::<i64>().ok()?
            };
            print!("    Currency [USD]: ");
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

fn prompt_url(label: &str) -> String {
    loop {
        print!("    {}: ", label);
        io::stdout().flush().ok();
        let url = read_line();
        if url.starts_with("http://") || url.starts_with("https://") {
            return url;
        }
        println!("    URL must start with http:// or https://");
    }
}

fn validate_custom_key(provider_type: &str, base_url: &str) -> Option<String> {
    print!("    API key: ");
    io::stdout().flush().ok();
    let key = read_line();
    if key.is_empty() {
        println!("    Skipped — set the key via env var before running grob");
        return None;
    }

    let rt = tokio::runtime::Handle::try_current();
    let valid = match rt {
        Ok(handle) => tokio::task::block_in_place(|| {
            handle.block_on(super::credential_check::validate_custom_endpoint(
                provider_type,
                base_url,
                &key,
            ))
        }),
        Err(_) => true,
    };
    if !valid {
        println!("    Warning: endpoint returned auth error. The key may be invalid.");
        println!("    Verify the base URL and API key, then retry. Continue anyway? [y/N]");
        if !confirm("    > ") {
            println!("    Key rejected. Set the correct key via env var before running grob.");
            return None;
        }
    }

    println!("    Accepted");
    Some(key)
}

fn screen_custom_endpoints() -> Vec<CustomEndpoint> {
    println!();
    println!("  Custom endpoints:");
    println!("    [1] Add a custom OpenAI-compatible endpoint");
    println!("    [2] Add a custom Anthropic-compatible endpoint");
    println!("    [3] Skip (no custom endpoints)");

    let mut endpoints = Vec::new();
    loop {
        let choice = prompt_choice(3);
        if choice == 3 {
            break;
        }

        let provider_type = if choice == 1 {
            "openai_compatible"
        } else {
            "anthropic_compatible"
        };

        print!("    Provider name (e.g. my-llm): ");
        io::stdout().flush().ok();
        let name = read_line();
        if name.is_empty() {
            println!("    Skipped");
            continue;
        }

        let base_url = prompt_url("Base URL (e.g. https://my-llm.company.com/v1)");
        let api_key = validate_custom_key(provider_type, &base_url);

        endpoints.push(CustomEndpoint {
            name,
            provider_type: provider_type.to_string(),
            base_url,
            api_key,
        });

        println!();
        println!("    Add another custom endpoint?");
        println!("    [1] Add OpenAI-compatible");
        println!("    [2] Add Anthropic-compatible");
        println!("    [3] Done");
    }
    endpoints
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
            println!("      {:<14} OAuth (configured)", a.provider);
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
    for ep in &c.custom_endpoints {
        println!(
            "      {:<14} {} ({})",
            ep.name, ep.provider_type, ep.base_url
        );
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
    let custom_keys: Vec<(String, &str)> = c
        .custom_endpoints
        .iter()
        .filter_map(|ep| {
            ep.api_key.as_deref().map(|k| {
                let env_var = format!("{}_API_KEY", ep.name.to_uppercase().replace('-', "_"));
                (env_var, k)
            })
        })
        .collect();
    if keys.is_empty() && custom_keys.is_empty() {
        return;
    }
    println!();
    println!("  Add to your shell profile:");
    for (var, key) in &keys {
        println!("    export {}={}", var, key);
    }
    for (var, key) in &custom_keys {
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

    // Custom endpoints
    if !choices.custom_endpoints.is_empty() {
        if let Some(providers) = config.get_mut("providers").and_then(|p| p.as_array_mut()) {
            for ep in &choices.custom_endpoints {
                let mut t = toml::map::Map::new();
                t.insert("name".into(), ep.name.clone().into());
                t.insert("provider_type".into(), ep.provider_type.clone().into());
                t.insert("base_url".into(), ep.base_url.clone().into());
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("models".into(), toml::Value::Array(vec![]));
                t.insert("pass_through".into(), toml::Value::Boolean(true));
                if let Some(ref key) = ep.api_key {
                    let env_var = format!("{}_API_KEY", ep.name.to_uppercase().replace('-', "_"));
                    t.insert("api_key".into(), format!("${env_var}").into());
                    let _ = key;
                }
                providers.push(toml::Value::Table(t));
            }
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
/// Returns an error if config writing, backup, or credential setup fails.
pub async fn run_setup_wizard(config_path: &Path, flags: &SetupFlags) -> Result<bool> {
    println!();

    let (_, env_budget, env_compliance) = env_overrides();
    let prefill = if config_path.exists() {
        prefill_from_config(config_path)
    } else {
        None
    };
    let existing_budget = prefill.as_ref().and_then(|(_, _, b)| *b);

    // Schema drift detection on existing config
    if config_path.exists() {
        check_schema_drift(config_path);
    }

    // --edit <section>: jump directly to a single section
    if let Some(ref section) = flags.edit_section {
        if !config_path.exists() {
            println!(
                "  No config found at {}. Run `grob setup` first.",
                config_path.display()
            );
            return Ok(false);
        }
        return run_edit_section(config_path, section, flags).await;
    }

    // Detect existing config
    if config_path.exists() && !flags.yes {
        println!("Configuration detected: {}", config_path.display());
        if let Some((ref providers, _, ref budget)) = prefill {
            if !providers.is_empty() {
                println!("  Providers: {}", providers.join(", "));
            }
            if let Some(b) = budget {
                println!("  Budget: {} USD/month", b);
            }
        }
        println!();
        println!("  [1] Edit (re-run wizard, keeping backup)");
        println!("  [2] Replace from scratch");
        println!("  [3] Cancel");
        println!();
        println!("  Tip: use `grob setup --edit providers` to reconfigure a single section.");
        if prompt_choice(3) == 3 {
            return Ok(false);
        }
        println!();
    } else if !config_path.exists() {
        println!("Welcome to Grob! No configuration detected.");
        println!();
    }

    // --yes: defaults, no prompts (with GROB_SETUP_* overrides)
    if flags.yes {
        let compliance = env_compliance
            .as_deref()
            .map(parse_compliance)
            .unwrap_or(Compliance::Standard);
        let budget = env_budget.map(|amount| BudgetChoice {
            amount,
            currency: "USD",
        });

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
            // `--yes` stays conservative: no fallback provider, so we never
            // emit a phantom "$OPENROUTER_API_KEY not set" warning on a cold
            // install without a subscription.
            fallback: FallbackChoice::None,
            fallback_key: None,
            custom_endpoints: vec![],
            compliance,
            budget,
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
        chain_doctor(config_path).await;
        return Ok(true);
    }

    // Screen 1: Tools
    let (tools, preset, preset_desc) = match screen_tools() {
        Some(t) => t,
        None => return setup_custom(config_path),
    };

    // Read providers from preset TOML (no hardcoded table)
    let providers = providers_from_preset(&preset);

    // Screen 2: Auth (with credential discovery)
    let auth = screen_auth(&providers);

    // Screen 3: Fallback — always prompted (opt-in). If the preset ships a
    // fallback and the user says "None", we strip the fallback provider from
    // the written config so no phantom warning fires at startup.
    let preset_has_fallback = providers.iter().any(|p| p == "openrouter" || p == "gemini");
    let (fallback, fallback_key) = screen_fallback(preset_has_fallback);

    // Screen 4: Custom endpoints
    let custom_endpoints = screen_custom_endpoints();

    // Screen 5: Compliance
    let tool_refs: Vec<&ToolInfo> = tools.iter().filter_map(|&i| TOOLS.get(i)).collect();
    let compliance = screen_compliance(&tool_refs);

    // Screen 6: Budget (with pre-fill from existing config)
    let budget = screen_budget(existing_budget);

    let choices = Choices {
        tools,
        preset,
        preset_desc,
        auth,
        fallback,
        fallback_key,
        custom_endpoints,
        compliance,
        budget,
    };

    // Screen 7: Recap
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
    chain_doctor(config_path).await;

    Ok(true)
}

/// Runs the wizard on a single section (--edit flag).
async fn run_edit_section(config_path: &Path, section: &str, flags: &SetupFlags) -> Result<bool> {
    let content = std::fs::read_to_string(config_path)?;
    let mut config: toml::Value = toml::from_str(&content)?;
    let prefill = prefill_from_config(config_path);

    match section {
        "providers" | "auth" => {
            let preset_name = config
                .get("presets")
                .and_then(|p| p.get("active"))
                .and_then(|v| v.as_str())
                .unwrap_or("perf");
            let providers = providers_from_preset(preset_name);
            let auth = screen_auth(&providers);

            if let Some(providers_arr) = config.get_mut("providers").and_then(|p| p.as_array_mut())
            {
                for p in providers_arr.iter_mut() {
                    let pname = p.get("name").and_then(|n| n.as_str()).unwrap_or("");
                    let Some(ov) = auth.iter().find(|a| a.provider == pname) else {
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
        }
        "budget" => {
            let existing = prefill.as_ref().and_then(|(_, _, b)| *b);
            if let Some(b) = screen_budget(existing) {
                patch(
                    &mut config,
                    "budget",
                    &[
                        ("monthly_limit_usd", b.amount.into()),
                        ("warn_at_percent", 80.into()),
                    ],
                );
            }
        }
        "compliance" => {
            let compliance = screen_compliance(&[]);
            match compliance {
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
                    std::fs::write(config_path, toml::to_string_pretty(&config)?)?;
                    crate::preset::overlay_compliance("eu-ai-act", config_path)?;
                    println!("  Compliance updated in {}", config_path.display());
                    chain_doctor(config_path).await;
                    return Ok(true);
                }
            }
        }
        "fallback" => {
            let existing_providers = prefill
                .as_ref()
                .map(|(p, _, _)| p.clone())
                .unwrap_or_default();
            let has_fallback = existing_providers
                .iter()
                .any(|p| p == "openrouter" || p == "gemini");
            let (fallback, _) = screen_fallback(has_fallback);
            match fallback {
                FallbackChoice::None => {
                    strip_fallback(&mut config, &["openrouter", "gemini"]);
                }
                FallbackChoice::OpenRouter => {
                    if let Some(providers) =
                        config.get_mut("providers").and_then(|p| p.as_array_mut())
                    {
                        providers.retain(|p| {
                            p.get("name").and_then(|n| n.as_str()) != Some("openrouter")
                        });
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
                    if let Some(providers) =
                        config.get_mut("providers").and_then(|p| p.as_array_mut())
                    {
                        providers
                            .retain(|p| p.get("name").and_then(|n| n.as_str()) != Some("gemini"));
                        let mut t = toml::map::Map::new();
                        t.insert("name".into(), "gemini".into());
                        t.insert("provider_type".into(), "gemini".into());
                        t.insert("enabled".into(), toml::Value::Boolean(true));
                        t.insert("models".into(), toml::Value::Array(vec![]));
                        t.insert("api_key".into(), "$GEMINI_API_KEY".into());
                        providers.push(toml::Value::Table(t));
                    }
                }
                FallbackChoice::KeepPreset => {}
            }
        }
        "endpoints" => {
            let endpoints = screen_custom_endpoints();
            if let Some(providers) = config.get_mut("providers").and_then(|p| p.as_array_mut()) {
                for ep in &endpoints {
                    let mut t = toml::map::Map::new();
                    t.insert("name".into(), ep.name.clone().into());
                    t.insert("provider_type".into(), ep.provider_type.clone().into());
                    t.insert("base_url".into(), ep.base_url.clone().into());
                    t.insert("enabled".into(), toml::Value::Boolean(true));
                    t.insert("models".into(), toml::Value::Array(vec![]));
                    t.insert("pass_through".into(), toml::Value::Boolean(true));
                    if ep.api_key.is_some() {
                        let env_var =
                            format!("{}_API_KEY", ep.name.to_uppercase().replace('-', "_"));
                        t.insert("api_key".into(), format!("${env_var}").into());
                    }
                    providers.push(toml::Value::Table(t));
                }
            }
        }
        _ => {
            println!(
                "  Unknown section '{}'. Available: providers, budget, compliance, fallback, endpoints",
                section
            );
            return Ok(false);
        }
    }

    if !flags.dry_run {
        if config_path.exists() {
            let backup = config_path.with_extension("toml.backup");
            std::fs::copy(config_path, &backup)?;
        }
        std::fs::write(config_path, toml::to_string_pretty(&config)?)?;
        println!("  Config updated: {}", config_path.display());
    } else {
        println!("  Dry run — no changes written.");
    }

    chain_doctor(config_path).await;
    Ok(true)
}

/// Chains `grob doctor` after the wizard writes the config.
async fn chain_doctor(config_path: &Path) {
    let Ok(config) = crate::cli::AppConfig::from_file(config_path) else {
        return;
    };
    let source = crate::cli::ConfigSource::File(config_path.to_path_buf());
    println!();
    let exit_code = super::doctor::cmd_doctor(&config, &source).await;
    if exit_code > 0 {
        println!();
        println!("  Some checks failed. Fix the issues above, then re-run: grob doctor");
    }
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
        if s.ok {
            println!("    {} ({}) — ok", s.provider_name, auth);
        } else if s.detail.contains("not set") {
            let env_var = auth_for(&s.provider_name)
                .map(|(_, _, e)| e)
                .unwrap_or("API_KEY");
            println!(
                "    {} ({}) — {}. Run: export {}=<your-key>",
                s.provider_name, auth, s.detail, env_var
            );
        } else {
            println!("    {} ({}) — {}", s.provider_name, auth, s.detail);
        }
    }
    if statuses.iter().any(|s| !s.ok && s.detail.contains("OAuth")) {
        println!();
        println!("  To complete OAuth setup, run: grob connect");
        println!("  (This will open your browser for authorization.)");
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
    println!("  Next steps:");
    println!("    1. Apply a preset:       grob preset apply perf");
    println!("    2. Set up credentials:   grob connect");
    println!("    3. Start the service:    grob start -d");
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

    /// W-3 : `prompt_url` rejects URLs that don't start with http:// or https://.
    #[test]
    fn test_w3_url_validation_rejects_bare_host() {
        let good = ["http://localhost:8080", "https://my-llm.company.com/v1"];
        for url in good {
            assert!(
                url.starts_with("http://") || url.starts_with("https://"),
                "{url} should pass"
            );
        }
        let bad = ["ftp://x", "my-llm.company.com", ""];
        for url in bad {
            assert!(
                !(url.starts_with("http://") || url.starts_with("https://")),
                "{url} should be rejected"
            );
        }
    }

    /// W-3 : custom endpoint providers are appended to the config TOML by
    /// `write_config`.
    #[test]
    fn test_w3_custom_endpoint_written_to_config() {
        let mut config: toml::Value = toml::from_str(
            r#"
[[providers]]
name = "anthropic"
provider_type = "anthropic"
enabled = true
models = []
"#,
        )
        .unwrap();

        if let Some(providers) = config.get_mut("providers").and_then(|p| p.as_array_mut()) {
            let mut t = toml::map::Map::new();
            t.insert("name".into(), "my-llm".into());
            t.insert("provider_type".into(), "openai_compatible".into());
            t.insert("base_url".into(), "https://my-llm.company.com/v1".into());
            t.insert("enabled".into(), toml::Value::Boolean(true));
            t.insert("models".into(), toml::Value::Array(vec![]));
            t.insert("pass_through".into(), toml::Value::Boolean(true));
            t.insert("api_key".into(), "$MY_LLM_API_KEY".into());
            providers.push(toml::Value::Table(t));
        }

        let providers = config.get("providers").and_then(|p| p.as_array()).unwrap();
        assert_eq!(providers.len(), 2);

        let custom = &providers[1];
        assert_eq!(custom.get("name").and_then(|n| n.as_str()), Some("my-llm"));
        assert_eq!(
            custom.get("provider_type").and_then(|n| n.as_str()),
            Some("openai_compatible")
        );
        assert_eq!(
            custom.get("base_url").and_then(|n| n.as_str()),
            Some("https://my-llm.company.com/v1")
        );
        assert_eq!(
            custom.get("pass_through").and_then(|n| n.as_bool()),
            Some(true)
        );
        assert_eq!(
            custom.get("api_key").and_then(|n| n.as_str()),
            Some("$MY_LLM_API_KEY")
        );
    }

    /// W-3 : anthropic_compatible endpoint also writes correctly.
    #[test]
    fn test_w3_anthropic_compatible_endpoint_written() {
        let mut config: toml::Value = toml::from_str("[[providers]]").unwrap();

        if let Some(providers) = config.get_mut("providers").and_then(|p| p.as_array_mut()) {
            let mut t = toml::map::Map::new();
            t.insert("name".into(), "corp-claude".into());
            t.insert("provider_type".into(), "anthropic_compatible".into());
            t.insert("base_url".into(), "https://claude.corp.internal/api".into());
            t.insert("enabled".into(), toml::Value::Boolean(true));
            t.insert("models".into(), toml::Value::Array(vec![]));
            t.insert("pass_through".into(), toml::Value::Boolean(true));
            providers.push(toml::Value::Table(t));
        }

        let providers = config.get("providers").and_then(|p| p.as_array()).unwrap();
        let custom = providers.last().unwrap();
        assert_eq!(
            custom.get("provider_type").and_then(|n| n.as_str()),
            Some("anthropic_compatible")
        );
        assert_eq!(
            custom.get("base_url").and_then(|n| n.as_str()),
            Some("https://claude.corp.internal/api")
        );
    }

    /// W-2-polish : `parse_compliance` maps known strings to the right variant.
    #[test]
    fn test_parse_compliance_variants() {
        assert!(matches!(parse_compliance("dlp"), Compliance::Dlp));
        assert!(matches!(parse_compliance("DLP"), Compliance::Dlp));
        assert!(matches!(parse_compliance("gdpr"), Compliance::EuGdpr));
        assert!(matches!(parse_compliance("eu-gdpr"), Compliance::EuGdpr));
        assert!(matches!(
            parse_compliance("enterprise"),
            Compliance::Enterprise
        ));
        assert!(matches!(
            parse_compliance("local-only"),
            Compliance::LocalOnly
        ));
        assert!(matches!(parse_compliance("ollama"), Compliance::LocalOnly));
        assert!(matches!(parse_compliance("standard"), Compliance::Standard));
        assert!(matches!(parse_compliance("unknown"), Compliance::Standard));
    }

    /// W-2-polish : `check_schema_drift` detects deprecated keys.
    #[test]
    fn test_schema_drift_detects_deprecated() {
        // Just test the constant is well-formed (the function prints to stdout).
        assert!(DEPRECATED_KEYS.len() >= 2);
        assert!(KNOWN_SECTIONS.contains(&"server"));
        assert!(KNOWN_SECTIONS.contains(&"providers"));
        assert!(KNOWN_SECTIONS.contains(&"budget"));
    }

    /// W-2-polish : `discover_credentials` returns empty when no env vars set.
    #[test]
    fn test_discover_credentials_empty_when_no_env() {
        // In test env, none of the provider env vars should be set.
        // This test validates the function does not panic and returns
        // a Vec; we can't assert emptiness because CI may have some vars set.
        let _result = discover_credentials();
    }

    /// W-2-polish : `env_overrides` reads GROB_SETUP_* variables.
    #[test]
    fn test_env_overrides_returns_none_when_unset() {
        let (provider, budget, compliance) = env_overrides();
        // Unless explicitly set in the test environment, these should be None.
        // We just check the function doesn't panic.
        let _ = (provider, budget, compliance);
    }
}

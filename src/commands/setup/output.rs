//! Recap, status, and post-write output helpers.
//!
//! Invoked at the end of the wizard to summarise the choices, chain
//! credential setup, run `grob doctor`, and emit usage hints.

use std::path::Path;

use anyhow::Result;

use super::detect::auth_for;
use super::input::confirm;
use super::types::{Choices, Compliance, FallbackChoice, SetupFlags, TOOLS};

/// Prints the recap and, unless `auto_confirm`, asks for confirmation.
///
/// Returns `true` when the caller should proceed with the write.
pub(in crate::commands::setup) fn display_recap(
    c: &Choices,
    path: &Path,
    dry_run: bool,
    auto_confirm: bool,
) -> bool {
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

/// Prints the `export FOO=bar` lines for keys entered during the wizard.
pub(in crate::commands::setup) fn print_exports(c: &Choices) {
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

/// Chains `grob doctor` after the wizard writes the config.
pub(in crate::commands::setup) async fn chain_doctor(config_path: &Path) {
    let Ok(config) = crate::models::config::AppConfig::from_file(config_path) else {
        return;
    };
    let source = crate::cli::ConfigSource::File(config_path.to_path_buf());
    println!();
    let exit_code = crate::commands::doctor::cmd_doctor(&config, &source).await;
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
pub(in crate::commands::setup) async fn chain_auto_flow(config_path: &Path, flags: &SetupFlags) {
    if flags.yes || !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return;
    }
    let Ok(config) = crate::models::config::AppConfig::from_file(config_path) else {
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

/// Prints the per-provider credential status after the wizard writes.
pub(in crate::commands::setup) fn print_status(config_path: &Path) {
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

/// Writes a minimal default config when the user picks the "Custom setup" option.
pub(in crate::commands::setup) fn setup_custom(config_path: &Path) -> Result<bool> {
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

/// Prints per-tool invocation hints ("How to use") for every tool the user selected in the wizard.
pub(in crate::commands::setup) fn print_usage(choices: &Choices) {
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

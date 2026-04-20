//! Interactive first-run setup wizard.
//!
//! Collects all choices upfront, displays a recap for confirmation,
//! then writes config atomically in a single pass.

use std::path::Path;

use anyhow::Result;

mod detect;
mod input;
mod output;
mod screens;
mod types;
mod writer;

pub use types::SetupFlags;

use detect::{
    check_schema_drift, env_overrides, parse_compliance, prefill_from_config, providers_from_preset,
};
use input::prompt_choice;
use output::{
    chain_auto_flow, chain_doctor, display_recap, print_exports, print_status, print_usage,
    setup_custom,
};
use screens::auth::screen_auth;
use screens::budget::screen_budget;
use screens::compliance::screen_compliance;
use screens::endpoints::screen_custom_endpoints;
use screens::fallback::screen_fallback;
use screens::tools::screen_tools;
use types::{AuthOverride, BudgetChoice, Choices, Compliance, FallbackChoice, ToolInfo, TOOLS};
use writer::{apply_auth_overrides, apply_compliance, apply_fallback, patch, write_config};

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
            apply_auth_overrides(&mut config, &auth);
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
                )?;
            }
        }
        "compliance" => {
            let compliance = screen_compliance(&[]);
            if apply_compliance(&mut config, compliance, config_path)? {
                println!("  Compliance updated in {}", config_path.display());
                chain_doctor(config_path).await;
                return Ok(true);
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
            apply_fallback(&mut config, &fallback);
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

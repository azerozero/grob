// Grob - High-performance LLM routing proxy
// Copyright (c) 2025-2026 A00 SASU
// License: AGPL-3.0-only
// See LICENSE for details

#[cfg(feature = "jemalloc")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use clap::Parser;
use std::io::IsTerminal;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

use grob::cli;
use grob::cli::args::{
    detect_bare_trailing_cmd, Cli, Commands, KeyAction, LogsAction, PresetAction, SecretsAction,
};
use grob::commands;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // W-4 : intercept `grob -- <cmd>` before clap parses it, so the user
    // gets an actionable hint instead of a generic `unexpected argument`.
    let raw_args: Vec<String> = std::env::args().collect();
    if let Some(suggestion) = detect_bare_trailing_cmd(&raw_args) {
        eprintln!("error: `grob -- <cmd>` is not a valid shortcut.");
        eprintln!();
        eprintln!("  did you mean: {suggestion} ?");
        std::process::exit(2);
    }

    let cli_args = Cli::parse();

    let command = if let Some(cmd) = cli_args.command {
        cmd
    } else {
        use clap::CommandFactory;
        Cli::command().print_help()?;
        return Ok(());
    };

    let config_source = match &cli_args.config {
        Some(val) if val.starts_with("http://") || val.starts_with("https://") => {
            cli::ConfigSource::Url(val.clone())
        }
        Some(val) => cli::ConfigSource::File(PathBuf::from(val)),
        None => cli::ConfigSource::File(
            cli::AppConfig::default_path().unwrap_or_else(|_| PathBuf::from("config/default.toml")),
        ),
    };

    // First-run setup wizard: trigger on `grob setup` or when config doesn't exist
    // for start/exec commands (interactive TTY only).
    let (wizard_yes, wizard_dry_run, wizard_edit) = match &command {
        Commands::Setup { yes, dry_run, edit } => (*yes, *dry_run, edit.clone()),
        _ => (false, false, None),
    };
    let needs_wizard = matches!(command, Commands::Setup { .. })
        || (matches!(command, Commands::Start { .. } | Commands::Exec { .. })
            && matches!(&config_source, cli::ConfigSource::File(p) if cli::AppConfig::needs_first_run(p))
            && std::io::stdin().is_terminal());

    if needs_wizard {
        let config_path = match &config_source {
            cli::ConfigSource::File(p) => p.clone(),
            cli::ConfigSource::Url(_) => cli::AppConfig::default_path()
                .unwrap_or_else(|_| PathBuf::from("config/default.toml")),
        };
        let flags = commands::setup::SetupFlags {
            yes: wizard_yes,
            dry_run: wizard_dry_run,
            edit_section: wizard_edit,
        };
        let completed = commands::setup::run_setup_wizard(&config_path, &flags).await?;
        if !completed {
            return Ok(());
        }
    }

    // Fail fast if config still absent after wizard opportunity (non-TTY or wizard skipped).
    if matches!(&config_source, cli::ConfigSource::File(p) if cli::AppConfig::needs_first_run(p))
        && matches!(
            command,
            Commands::Start { .. } | Commands::Run { .. } | Commands::Exec { .. }
        )
    {
        eprintln!("No configuration found.");
        eprintln!("  Run 'grob setup' interactively or create ~/.grob/config.toml");
        eprintln!("  Quick start: grob preset apply perf");
        std::process::exit(1);
    }

    let mut config = cli::AppConfig::from_source(&config_source).await?;
    config = cli::merge_project_config(config);

    let (use_json_logs, log_level_override) = match &command {
        Commands::Run {
            json_logs,
            log_level,
            ..
        } => (*json_logs, log_level.clone()),
        _ => (false, None),
    };

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        let level = log_level_override
            .as_deref()
            .unwrap_or(&config.server.log_level);
        EnvFilter::new(level)
    });
    // Initialize tracing subscriber (with optional OpenTelemetry layer).
    #[cfg(feature = "otel")]
    {
        if config.otel.enabled {
            match grob::shared::otel::init_subscriber_with_otel(&config.otel, filter, use_json_logs)
            {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("OpenTelemetry init failed: {}", e);
                    std::process::exit(1);
                }
            }
        } else if use_json_logs {
            tracing_subscriber::fmt()
                .json()
                .with_env_filter(filter)
                .init();
        } else {
            tracing_subscriber::fmt().with_env_filter(filter).init();
        }
    }

    #[cfg(not(feature = "otel"))]
    {
        if use_json_logs {
            tracing_subscriber::fmt()
                .json()
                .with_env_filter(filter)
                .init();
        } else {
            tracing_subscriber::fmt().with_env_filter(filter).init();
        }
    }

    match command {
        Commands::Start { port, detach } => {
            commands::start::cmd_start(config, config_source, port, detach, cli_args.config)
                .await?;
        }
        Commands::Stop => commands::stop::cmd_stop(&config).await?,
        Commands::Restart { detach } => {
            commands::restart::cmd_restart(config, config_source, detach, cli_args.config).await?;
        }
        Commands::Status => commands::status::cmd_status(&config).await?,
        Commands::Spend => commands::spend::cmd_spend(&config).await,
        Commands::Model => commands::model::cmd_model(&config).await,
        Commands::Validate => commands::validate::cmd_validate(&config).await?,
        Commands::Run {
            port,
            host,
            log_level: _,
            json_logs: _,
        } => commands::run::cmd_run(config, config_source, port, host).await?,
        Commands::Preset { action } => match action {
            PresetAction::List => commands::preset::cmd_preset_list(&config).await,
            PresetAction::Info { name } => commands::preset::cmd_preset_info(&name),
            PresetAction::Install { source } => commands::preset::cmd_preset_install(&source).await,
            PresetAction::Apply {
                name,
                reload,
                dry_run,
            } => {
                commands::preset::cmd_preset_apply(&name, &config_source, &config, reload, dry_run)
                    .await?;
            }
            PresetAction::Export { name, env } => {
                commands::preset::cmd_preset_export(&name, &config_source, env.as_deref())?;
            }
            PresetAction::Sync => commands::preset::cmd_preset_sync(&config).await,
            PresetAction::Push { name, target, yes } => {
                commands::config_promote::cmd_config_push(&name, &target, yes).await?;
            }
            PresetAction::Pull { from, save } => {
                commands::config_promote::cmd_config_pull(&from, &save).await?;
            }
        },
        Commands::Exec { port, no_stop, cmd } => {
            commands::exec::cmd_exec(&config, port, no_stop, cmd, cli_args.config).await?;
        }
        Commands::Completions { shell } => commands::completions::cmd_completions::<Cli>(shell),
        Commands::SetupCompletions => commands::setup_completions::cmd_setup_completions::<Cli>()?,
        Commands::Env => commands::env::cmd_env(&config),
        Commands::Connect {
            provider,
            force_reauth,
        } => {
            commands::connect::cmd_connect(&config, &config_source, provider, force_reauth).await?;
        }
        Commands::Init => commands::init::cmd_init()?,
        Commands::ConfigDiff { target } => {
            commands::config_diff::cmd_config_diff(&config, &config_source, target)?;
        }
        Commands::Setup { .. } => {
            // Already handled above; if we reach here, wizard already ran.
        }
        Commands::Logs { action } => match action {
            LogsAction::Decrypt { path, output } => {
                commands::logs::cmd_logs_decrypt(path, output)?;
            }
        },
        Commands::Key { action } => match action {
            KeyAction::Create {
                name,
                tenant,
                budget,
                rate_limit,
                allowed_models,
                expires,
            } => {
                commands::key::cmd_key_create(
                    &config,
                    &name,
                    &tenant,
                    budget,
                    rate_limit,
                    allowed_models,
                    expires,
                )
                .await
            }
            KeyAction::List { json } => commands::key::cmd_key_list(&config, json).await,
            KeyAction::Revoke { id_or_prefix } => {
                commands::key::cmd_key_revoke(&config, &id_or_prefix).await
            }
        },
        Commands::Secrets { action } => match action {
            SecretsAction::Add { name } => commands::secrets::cmd_secrets_add(&name),
            SecretsAction::List { json } => commands::secrets::cmd_secrets_list(json),
            SecretsAction::Show { name, unsafe_show } => {
                commands::secrets::cmd_secrets_show(&name, unsafe_show)
            }
            SecretsAction::Rm { name, force } => commands::secrets::cmd_secrets_rm(&name, force),
            SecretsAction::Test { name, json } => {
                commands::secrets::cmd_secrets_test(&config, name.as_deref(), json).await
            }
        },
        Commands::Rollback => {
            commands::config_rollback::cmd_config_rollback(&config, &config_source).await?;
        }
        Commands::Bench {
            requests,
            with_auth,
            format,
            concurrency,
            payload,
            escalate,
        } => {
            commands::bench::cmd_bench(
                &config,
                requests,
                with_auth,
                &format,
                concurrency,
                &payload,
                escalate,
            )
            .await?
        }
        Commands::Doctor => {
            let exit_code = commands::doctor::cmd_doctor(&config, &config_source).await;
            if exit_code > 0 {
                std::process::exit(exit_code as i32);
            }
        }
        #[cfg(feature = "watch")]
        Commands::Watch => {
            let base_url = cli::format_base_url(&config.server.host, config.server.port.value());
            grob::features::watch::tui::run(&base_url).await?;
        }
        Commands::Upgrade => commands::upgrade::cmd_upgrade(&config, cli_args.config).await?,
        #[cfg(feature = "harness")]
        Commands::Harness { action } => {
            commands::harness::cmd_harness(&config, action).await?;
        }
    }

    Ok(())
}

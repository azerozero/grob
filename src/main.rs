// Grob - High-performance LLM routing proxy
// Copyright (c) 2025-2026 A00 SASU
// License: AGPL-3.0-only
// See LICENSE for details

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use clap::Parser;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

use grob::cli;
use grob::cli::args::{Cli, Commands, PresetAction};
use grob::commands;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli_args = Cli::parse();

    let command = if let Some(cmd) = cli_args.command {
        cmd
    } else if !cli_args.trailing_cmd.is_empty() {
        Commands::Exec {
            port: None,
            no_stop: false,
            cmd: cli_args.trailing_cmd,
        }
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
    if use_json_logs {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
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
        Commands::Spend => commands::spend::cmd_spend(&config),
        Commands::Model => commands::model::cmd_model(&config),
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
            PresetAction::Apply { name } => {
                commands::preset::cmd_preset_apply(&name, &config_source)?;
            }
            PresetAction::Export { name } => {
                commands::preset::cmd_preset_export(&name, &config_source)?;
            }
            PresetAction::Sync => commands::preset::cmd_preset_sync(&config).await,
        },
        Commands::Exec { port, no_stop, cmd } => {
            commands::exec::cmd_exec(&config, port, no_stop, cmd, cli_args.config).await?;
        }
        Commands::Completions { shell } => commands::completions::cmd_completions::<Cli>(shell),
        Commands::SetupCompletions => commands::setup_completions::cmd_setup_completions::<Cli>()?,
        Commands::Env => commands::env::cmd_env(&config),
        Commands::Connect { provider } => {
            commands::connect::cmd_connect(&config, &config_source, provider)?;
        }
        Commands::Init => commands::init::cmd_init()?,
        Commands::ConfigDiff { target } => {
            commands::config_diff::cmd_config_diff(&config, &config_source, target)?;
        }
        Commands::Doctor => commands::doctor::cmd_doctor(&config, &config_source).await,
        Commands::Upgrade => commands::upgrade::cmd_upgrade(&config, cli_args.config).await?,
        #[cfg(feature = "harness")]
        Commands::Harness { action } => {
            commands::harness::cmd_harness(&config, action).await?;
        }
    }

    Ok(())
}

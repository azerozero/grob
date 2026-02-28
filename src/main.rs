// Grob - High-performance LLM routing proxy
// Copyright (c) 2025-2026 A00 SASU
// License: AGPL-3.0-only
// See LICENSE for details

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use clap::{Parser, Subcommand};
use clap_complete::Shell;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

use grob::{cli, commands};

#[derive(Parser)]
#[command(name = "grob")]
#[command(version)]
#[command(before_help = concat!("Grob v", env!("CARGO_PKG_VERSION")))]
#[command(about = "High-performance LLM routing proxy\n\nQuick start:\n  grob exec -- claude     Launch Claude Code through Grob\n  grob exec -- aider      Launch Aider through Grob\n  grob start -d           Start Grob in background\n  grob status             Show service status and models", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Path or URL to configuration file (defaults to ~/.grob/config.toml)
    /// Also settable via GROB_CONFIG env var
    #[arg(short, long, env = "GROB_CONFIG")]
    config: Option<String>,

    /// Shorthand: grob -- <cmd> is equivalent to grob exec -- <cmd>
    #[arg(last = true)]
    trailing_cmd: Vec<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the router service
    Start {
        #[arg(short, long)]
        port: Option<u16>,
        #[arg(short = 'd', long)]
        detach: bool,
    },
    /// Stop the router service
    Stop,
    /// Restart the router service
    Restart {
        #[arg(short = 'd', long)]
        detach: bool,
    },
    /// Check service status
    Status,
    /// Show current month's spend and budget
    Spend,
    /// Manage models and providers
    Model,
    /// Validate config: test all providers and models with real API calls
    Validate,
    /// Manage presets (list, apply, export, install, sync)
    Preset {
        #[command(subcommand)]
        action: PresetAction,
    },
    /// Run in container mode (foreground, 0.0.0.0, JSON logs, graceful shutdown, no PID file)
    Run {
        #[arg(short, long, env = "GROB_PORT")]
        port: Option<u16>,
        #[arg(long, env = "GROB_HOST")]
        host: Option<String>,
        #[arg(long, env = "GROB_LOG_LEVEL")]
        log_level: Option<String>,
        #[arg(long, env = "GROB_JSON_LOGS")]
        json_logs: bool,
    },
    /// Launch a command behind the Grob proxy (auto-starts/stops service)
    ///
    /// Examples:
    ///   grob exec -- claude
    ///   grob exec -- opencode
    ///   grob launch -- aider
    ///   grob exec --port 9000 -- my-tool --flag
    #[command(
        alias = "launch",
        long_about = "Launch a command behind the Grob proxy.\n\nAutomatically starts Grob if not running, sets ANTHROPIC_BASE_URL and\nOPENAI_BASE_URL environment variables, runs your command, and stops\nGrob when the command exits (unless --no-stop is set).\n\nExamples:\n  grob exec -- claude           # Run Claude Code through Grob\n  grob exec -- opencode          # Run OpenCode through Grob\n  grob launch -- aider           # 'launch' is an alias for 'exec'\n  grob exec --no-stop -- my-tool # Keep Grob running after exit"
    )]
    Exec {
        #[arg(short, long)]
        port: Option<u16>,
        #[arg(long)]
        no_stop: bool,
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
    /// Generate shell completions
    ///
    /// Output completions for the given shell to stdout.
    /// Example: grob completions zsh > ~/.zfunc/_grob
    Completions {
        #[arg(value_enum)]
        shell: Shell,
    },
    /// Install shell completions for your current shell (zsh, bash, fish)
    SetupCompletions,
    /// Check environment variables required by configured providers
    Env,
    /// Set up credentials for providers (interactive)
    ///
    /// Without arguments, checks all providers. With a provider name,
    /// sets up credentials for that specific provider only.
    Connect { provider: Option<String> },
    /// Initialize a per-project .grob.toml in the current directory
    Init,
    /// Compare local config against a preset or remote config
    ConfigDiff { target: Option<String> },
    /// Run diagnostic checks on your Grob installation
    Doctor,
    /// Zero-downtime upgrade: spawn new process, wait for health, signal old to drain
    ///
    /// Uses SO_REUSEPORT to run both old and new processes on the same port.
    /// The new process binds → passes health check → old process receives SIGUSR1 → drains.
    Upgrade,
}

#[derive(Subcommand)]
enum PresetAction {
    /// List available presets
    List,
    /// Show detailed info about a preset (providers, models, env vars)
    Info { name: String },
    /// Install presets from a git repo or local path
    Install { source: String },
    /// Apply a preset to config (backs up current config)
    Apply { name: String },
    /// Export current config as a reusable preset
    Export { name: String },
    /// Sync presets from configured git repo
    Sync,
}

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
            commands::start::cmd_start(config, config_source, port, detach, cli_args.config).await?
        }
        Commands::Stop => commands::stop::cmd_stop(&config).await?,
        Commands::Restart { detach } => {
            commands::restart::cmd_restart(config, config_source, detach, cli_args.config).await?
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
                commands::preset::cmd_preset_apply(&name, &config_source)?
            }
            PresetAction::Export { name } => {
                commands::preset::cmd_preset_export(&name, &config_source)?
            }
            PresetAction::Sync => commands::preset::cmd_preset_sync(&config).await,
        },
        Commands::Exec { port, no_stop, cmd } => {
            commands::exec::cmd_exec(&config, port, no_stop, cmd, cli_args.config).await?
        }
        Commands::Completions { shell } => commands::completions::cmd_completions::<Cli>(shell),
        Commands::SetupCompletions => commands::setup_completions::cmd_setup_completions::<Cli>()?,
        Commands::Env => commands::env::cmd_env(&config),
        Commands::Connect { provider } => {
            commands::connect::cmd_connect(&config, &config_source, provider)?
        }
        Commands::Init => commands::init::cmd_init()?,
        Commands::ConfigDiff { target } => {
            commands::config_diff::cmd_config_diff(&config, &config_source, target)?
        }
        Commands::Doctor => commands::doctor::cmd_doctor(&config, &config_source).await,
        Commands::Upgrade => commands::upgrade::cmd_upgrade(&config, cli_args.config).await?,
    }

    Ok(())
}

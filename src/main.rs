// Grob - High-performance LLM routing proxy
// Copyright (c) 2025 a00 SAS
// License: Elastic License v2.0
// See LICENSE for details

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::Command;
use tracing_subscriber::EnvFilter;

mod auth;
mod cli;
mod features;
mod message_tracing;
mod models;
mod pid;
mod preset;
mod providers;
mod router;
mod server;

const PROCESS_TRANSITION_GRACE_MS: u64 = 500;

async fn stop_service(pid: u32) -> anyhow::Result<()> {
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;
    kill(Pid::from_raw(pid as i32), Signal::SIGTERM)
        .map_err(|e| anyhow::anyhow!("Failed to stop service: {}", e))?;
    tokio::time::sleep(tokio::time::Duration::from_millis(
        PROCESS_TRANSITION_GRACE_MS,
    ))
    .await;
    Ok(())
}

async fn start_foreground(
    config: cli::AppConfig,
    config_source: cli::ConfigSource,
) -> anyhow::Result<()> {
    // Write PID file
    if let Err(e) = pid::write_pid() {
        eprintln!("Warning: Failed to write PID file: {}", e);
    }

    tracing::info!("Starting Grob on port {}", config.server.port);
    println!("🚀 Grob v{}", env!("CARGO_PKG_VERSION"));
    println!(
        "📡 Starting server on {}:{}",
        config.server.host, config.server.port
    );
    println!();

    // Display routing configuration
    println!("🔀 Router Configuration:");
    println!("   Default: {}", config.router.default);
    if let Some(ref bg) = config.router.background {
        println!("   Background: {}", bg);
    }
    if let Some(ref think) = config.router.think {
        println!("   Think: {}", think);
    }
    if let Some(ref ws) = config.router.websearch {
        println!("   WebSearch: {}", ws);
    }
    println!();
    println!("Press Ctrl+C to stop");

    let result = server::start_server(config, config_source).await;
    let _ = pid::cleanup_pid();
    result
}

fn spawn_background_service(port: Option<u16>, config: Option<String>) -> anyhow::Result<()> {
    let exe_path = std::env::current_exe()?;
    let mut cmd = Command::new(&exe_path);
    cmd.arg("start");

    if let Some(port) = port {
        cmd.arg("--port").arg(port.to_string());
    }
    if let Some(config) = config {
        cmd.arg("--config").arg(config);
    }

    {
        use std::os::unix::process::CommandExt;
        unsafe {
            cmd.pre_exec(|| {
                nix::libc::setsid();
                Ok(())
            });
        }
    }

    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    cmd.spawn()?;
    Ok(())
}

#[derive(Parser)]
#[command(name = "grob")]
#[command(about = "Grob - High-performance LLM routing proxy", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Path or URL to configuration file (defaults to ~/.grob/config.toml)
    /// Also settable via GROB_CONFIG env var
    #[arg(short, long, env = "GROB_CONFIG")]
    config: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the router service
    Start {
        /// Port to listen on
        #[arg(short, long)]
        port: Option<u16>,
        /// Run in detached/background mode
        #[arg(short = 'd', long)]
        detach: bool,
    },
    /// Stop the router service
    Stop,
    /// Restart the router service
    Restart {
        /// Run in detached/background mode
        #[arg(short = 'd', long)]
        detach: bool,
    },
    /// Check service status
    Status,
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
        /// Port to listen on
        #[arg(short, long, env = "GROB_PORT")]
        port: Option<u16>,
        /// Host to bind to (default: 0.0.0.0)
        #[arg(long, env = "GROB_HOST")]
        host: Option<String>,
        /// Log level (trace, debug, info, warn, error)
        #[arg(long, env = "GROB_LOG_LEVEL")]
        log_level: Option<String>,
        /// Use JSON-formatted logs (for structured logging in containers)
        #[arg(long, env = "GROB_JSON_LOGS")]
        json_logs: bool,
    },
}

#[derive(Subcommand)]
enum PresetAction {
    /// List available presets
    List,
    /// Show detailed info about a preset (providers, models, env vars)
    Info {
        /// Preset name
        name: String,
    },
    /// Install presets from a git repo or local path
    Install {
        /// Git URL or local path
        source: String,
    },
    /// Apply a preset to config (backs up current config)
    Apply {
        /// Preset name (perf, medium, cheap, local, or installed name)
        name: String,
    },
    /// Export current config as a reusable preset
    Export {
        /// Name for the exported preset
        name: String,
    },
    /// Sync presets from configured git repo
    Sync,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Resolve config source: --config / GROB_CONFIG (path or URL) or default
    let config_source = match &cli.config {
        Some(val) if val.starts_with("http://") || val.starts_with("https://") => {
            cli::ConfigSource::Url(val.clone())
        }
        Some(val) => cli::ConfigSource::File(PathBuf::from(val)),
        None => cli::ConfigSource::File(
            cli::AppConfig::default_path().unwrap_or_else(|_| PathBuf::from("config/default.toml")),
        ),
    };

    // Load configuration
    let config = cli::AppConfig::from_source(&config_source).await?;

    // Determine if we need JSON logs (only for `run --json-logs`)
    let (use_json_logs, log_level_override) = match &cli.command {
        Commands::Run {
            json_logs,
            log_level,
            ..
        } => (*json_logs, log_level.clone()),
        _ => (false, None),
    };

    // Initialize tracing: RUST_LOG env var takes precedence, then CLI flag, then config
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

    match cli.command {
        Commands::Start { port, detach } => {
            // If detached, spawn as background process
            if detach {
                println!("Starting Grob in background...");

                // Stop existing service if running
                if let Ok(pid) = pid::read_pid() {
                    if pid::is_process_running(pid) {
                        println!("Stopping existing service...");
                        if let Err(e) = stop_service(pid).await {
                            eprintln!("Warning: Failed to stop existing service: {}", e);
                        }
                    }
                }
                let _ = pid::cleanup_pid();

                // Start in background
                spawn_background_service(port, cli.config)?;
                tokio::time::sleep(tokio::time::Duration::from_millis(
                    PROCESS_TRANSITION_GRACE_MS,
                ))
                .await;

                if let Ok(pid) = pid::read_pid() {
                    println!("✅ Grob started in background (PID: {})", pid);
                } else {
                    println!("✅ Grob started in background");
                }
                println!("📡 Running on port {}", port.unwrap_or(config.server.port));
                return Ok(());
            }

            // Foreground mode
            let mut config = config;

            // Override port if specified
            if let Some(port) = port {
                config.server.port = port;
            }

            // Check if already running
            if let Ok(existing_pid) = pid::read_pid() {
                if pid::is_process_running(existing_pid) {
                    eprintln!(
                        "❌ Error: Service is already running (PID: {})",
                        existing_pid
                    );
                    eprintln!(
                        "Use 'grob stop' to stop it first, or use 'grob start -d' to restart it"
                    );
                    return Ok(());
                }
                // Stale PID file, clean it up
                let _ = pid::cleanup_pid();
            }

            start_foreground(config, config_source).await?;
        }
        Commands::Stop => {
            println!("Stopping Grob...");
            match pid::read_pid() {
                Ok(pid) if pid::is_process_running(pid) => match stop_service(pid).await {
                    Ok(_) => {
                        println!("✅ Service stopped successfully");
                        let _ = pid::cleanup_pid();
                    }
                    Err(e) => {
                        eprintln!("❌ Failed to stop service (PID: {}): {}", pid, e);
                    }
                },
                _ => {
                    println!("Service is not running");
                    let _ = pid::cleanup_pid();
                }
            }
        }
        Commands::Restart { detach } => {
            // Stop the existing service
            let was_running = match pid::read_pid() {
                Ok(pid) => {
                    if pid::is_process_running(pid) {
                        println!("Stopping existing service...");
                        match stop_service(pid).await {
                            Ok(_) => true,
                            Err(e) => {
                                eprintln!("Warning: Failed to stop existing service: {}", e);
                                false
                            }
                        }
                    } else {
                        false
                    }
                }
                Err(_) => false,
            };
            let _ = pid::cleanup_pid();

            if detach {
                // Background mode
                println!("Starting service in background...");
                let port_from_config = Some(config.server.port);
                spawn_background_service(port_from_config, cli.config.clone())?;
                tokio::time::sleep(tokio::time::Duration::from_millis(
                    PROCESS_TRANSITION_GRACE_MS,
                ))
                .await;

                let verb = if was_running { "restarted" } else { "started" };
                if let Ok(pid) = pid::read_pid() {
                    println!("✅ Service {} successfully (PID: {})", verb, pid);
                } else {
                    println!("✅ Service {} successfully", verb);
                }
            } else {
                // Foreground mode
                start_foreground(config, config_source).await?;
            }
        }
        Commands::Status => {
            println!("Checking service status...");
            match pid::read_pid() {
                Ok(pid) => {
                    if pid::is_process_running(pid) {
                        println!("✅ Service is running (PID: {})", pid);
                    } else {
                        println!("❌ Service is not running (stale PID file)");
                        let _ = pid::cleanup_pid();
                    }
                }
                Err(_) => {
                    println!("❌ Service is not running");
                }
            }
        }
        Commands::Model => {
            println!("📊 Model Configuration");
            println!();
            println!("Configured Models:");
            println!("  • Default: {}", config.router.default);
            if let Some(ref think) = config.router.think {
                println!("  • Think: {}", think);
            }
            if let Some(ref ws) = config.router.websearch {
                println!("  • WebSearch: {}", ws);
            }
            if let Some(ref bg) = config.router.background {
                println!("  • Background: {}", bg);
            }
            println!();
            println!("Providers:");
            for provider in &config.providers {
                if provider.enabled.unwrap_or(false) {
                    println!("  • {} ({})", provider.name, provider.provider_type);
                }
            }
        }
        Commands::Validate => {
            println!("🔍 Validating configuration...");
            println!();

            // Build provider registry
            let (registry, _token_store) = match preset::build_registry(&config) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("❌ Failed to initialize providers: {}", e);
                    eprintln!("   Fix your config and try again.");
                    return Ok(());
                }
            };

            println!(
                "  Testing {} model(s) with real API calls...",
                config.models.len()
            );
            println!();

            let results = preset::validate_config(&config, &registry).await;
            preset::print_validation_results(&results);
        }
        Commands::Run {
            port,
            host,
            log_level: _,
            json_logs: _,
        } => {
            // Container mode: no PID file, default 0.0.0.0, graceful shutdown
            let mut config = config;
            if let Some(port) = port {
                config.server.port = port;
            }
            config.server.host = host.unwrap_or_else(|| "0.0.0.0".to_string());

            tracing::info!(
                "🐳 Container mode: {}:{}",
                config.server.host,
                config.server.port
            );

            // Graceful shutdown via SIGTERM/SIGINT
            let shutdown = async {
                let ctrl_c = tokio::signal::ctrl_c();
                #[cfg(unix)]
                {
                    let mut sigterm =
                        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                            .expect("failed to register SIGTERM handler");
                    tokio::select! {
                        _ = ctrl_c => { tracing::info!("Received SIGINT, shutting down..."); }
                        _ = sigterm.recv() => { tracing::info!("Received SIGTERM, shutting down..."); }
                    }
                }
                #[cfg(not(unix))]
                {
                    ctrl_c.await.ok();
                    tracing::info!("Received SIGINT, shutting down...");
                }
            };

            tokio::select! {
                result = server::start_server(config, config_source) => {
                    result?;
                }
                _ = shutdown => {
                    tracing::info!("Graceful shutdown complete");
                }
            }
        }
        Commands::Preset { action } => match action {
            PresetAction::List => {
                println!("📦 Available Presets");
                println!();
                match preset::list_presets() {
                    Ok(presets) => {
                        for p in &presets {
                            let tag = if p.is_builtin { "builtin" } else { "installed" };
                            let active = if config.presets.active.as_deref() == Some(&p.name) {
                                " (active)"
                            } else {
                                ""
                            };
                            println!("  {} [{}]{}", p.name, tag, active);
                            println!("    {}", p.description);
                        }
                    }
                    Err(e) => eprintln!("Error listing presets: {}", e),
                }
            }
            PresetAction::Info { name } => match preset::print_preset_info(&name) {
                Ok(_) => {}
                Err(e) => eprintln!("❌ {}", e),
            },
            PresetAction::Install { source } => {
                println!("📥 Installing presets from {}...", source);
                match preset::install_from_source(&source).await {
                    Ok(_) => println!("✅ Installation complete"),
                    Err(e) => eprintln!("❌ Installation failed: {}", e),
                }
            }
            PresetAction::Apply { name } => {
                let file_path = match &config_source {
                    cli::ConfigSource::File(p) => p.clone(),
                    cli::ConfigSource::Url(_) => {
                        eprintln!("❌ Cannot apply presets to a remote URL config");
                        eprintln!("   Use a local config file instead");
                        return Ok(());
                    }
                };
                println!("🔧 Applying preset '{}'...", name);
                match preset::apply_preset(&name, &file_path) {
                    Ok(_) => {
                        if let Err(e) = preset::setup_credentials_interactive(&file_path) {
                            eprintln!("Warning: credential check failed: {}", e);
                        }

                        println!();
                        println!("✅ Preset '{}' applied successfully", name);
                        println!("   Run: grob start -d");
                    }
                    Err(e) => eprintln!("❌ Failed to apply preset: {}", e),
                }
            }
            PresetAction::Export { name } => {
                let file_path = match &config_source {
                    cli::ConfigSource::File(p) => p.clone(),
                    cli::ConfigSource::Url(_) => {
                        eprintln!("❌ Cannot export presets from a remote URL config");
                        return Ok(());
                    }
                };
                println!("📤 Exporting current config as preset '{}'...", name);
                match preset::export_preset(&name, &file_path) {
                    Ok(_) => println!("✅ Export complete"),
                    Err(e) => eprintln!("❌ Export failed: {}", e),
                }
            }
            PresetAction::Sync => {
                if let Some(ref url) = config.presets.sync_url {
                    println!("🔄 Syncing presets from {}...", url);
                    match preset::sync_presets(url).await {
                        Ok(_) => println!("✅ Sync complete"),
                        Err(e) => eprintln!("❌ Sync failed: {}", e),
                    }
                } else {
                    eprintln!("❌ No sync_url configured in [presets] section");
                    eprintln!("   Add to config.toml:");
                    eprintln!("   [presets]");
                    eprintln!("   sync_url = \"https://raw.githubusercontent.com/azerozero/grob/main/presets/\"");
                }
            }
        },
    }

    Ok(())
}

// Grob - High-performance LLM routing proxy
// Copyright (c) 2025-2026 A00 SASU
// License: AGPL-3.0-only
// See LICENSE for details

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};
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
mod security;
mod instance;
mod server;
mod storage;

const PROCESS_TRANSITION_GRACE_MS: u64 = 500;
const HEALTH_POLL_INTERVAL_MS: u64 = 100;
const HEALTH_POLL_MAX_ATTEMPTS: u32 = 50; // 50 * 100ms = 5s max

/// Check if Grob is healthy at the given base URL.
async fn is_grob_healthy(base_url: &str) -> bool {
    let url = format!("{}/health", base_url);
    match reqwest::Client::new()
        .get(&url)
        .timeout(std::time::Duration::from_secs(2))
        .send()
        .await
    {
        Ok(resp) => resp.status().is_success(),
        Err(_) => false,
    }
}

/// Poll the health endpoint until it returns 200 or max attempts reached.
async fn poll_health(base_url: &str, max_attempts: u32, interval_ms: u64) -> bool {
    for _ in 0..max_attempts {
        if is_grob_healthy(base_url).await {
            return true;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(interval_ms)).await;
    }
    false
}

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
        "📡 Starting server on {}",
        cli::format_bind_addr(&config.server.host, config.server.port)
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
#[command(about = "Grob - High-performance LLM routing proxy\n\nQuick start:\n  grob exec -- claude     Launch Claude Code through Grob\n  grob exec -- aider      Launch Aider through Grob\n  grob start -d           Start Grob in background\n  grob status             Show service status and models", long_about = None)]
#[command(version)]
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
    /// Launch a command behind the Grob proxy (auto-starts/stops service)
    ///
    /// Examples:
    ///   grob exec -- claude
    ///   grob exec -- opencode
    ///   grob launch -- aider
    ///   grob exec --port 9000 -- my-tool --flag
    #[command(alias = "launch", long_about = "Launch a command behind the Grob proxy.\n\nAutomatically starts Grob if not running, sets ANTHROPIC_BASE_URL and\nOPENAI_BASE_URL environment variables, runs your command, and stops\nGrob when the command exits (unless --no-stop is set).\n\nExamples:\n  grob exec -- claude           # Run Claude Code through Grob\n  grob exec -- opencode          # Run OpenCode through Grob\n  grob launch -- aider           # 'launch' is an alias for 'exec'\n  grob exec --no-stop -- my-tool # Keep Grob running after exit")]
    Exec {
        /// Port to use for the proxy
        #[arg(short, long)]
        port: Option<u16>,
        /// Don't stop Grob after the child exits
        #[arg(long)]
        no_stop: bool,
        /// Command and arguments to run
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
    /// Generate shell completions
    ///
    /// Output completions for the given shell to stdout.
    /// Example: grob completions zsh > ~/.zfunc/_grob
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: Shell,
    },
    /// Check environment variables required by configured providers
    Env,
    /// Set up credentials for providers (interactive)
    ///
    /// Without arguments, checks all providers. With a provider name,
    /// sets up credentials for that specific provider only.
    Connect {
        /// Provider name to configure (optional, configures all if omitted)
        provider: Option<String>,
    },
    /// Initialize a per-project .grob.toml in the current directory
    Init,
    /// Compare local config against a preset or remote config
    ConfigDiff {
        /// Preset name or URL to compare against
        target: Option<String>,
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

    // Handle shorthand: `grob -- cmd` → exec with trailing args
    let command = if let Some(cmd) = cli.command {
        cmd
    } else if !cli.trailing_cmd.is_empty() {
        // Treat trailing args as exec command
        Commands::Exec {
            port: None,
            no_stop: false,
            cmd: cli.trailing_cmd,
        }
    } else {
        // No command and no trailing args: show help
        Cli::command().print_help()?;
        return Ok(());
    };

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
    let mut config = cli::AppConfig::from_source(&config_source).await?;

    // Merge per-project .grob.toml overlay (if found)
    config = cli::merge_project_config(config);

    // Determine if we need JSON logs (only for `run --json-logs`)
    let (use_json_logs, log_level_override) = match &command {
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

    match command {
        Commands::Start { port, detach } => {
            let effective_port = port.unwrap_or(config.server.port);

            // If detached, spawn as background process
            if detach {
                println!("Starting Grob in background...");

                // Stop existing service if running (health-check based)
                if instance::is_instance_running(&config.server.host, effective_port).await {
                    println!("Stopping existing service...");
                    if let Some(pid) = instance::find_instance_pid(&config.server.host, effective_port).await {
                        if let Err(e) = stop_service(pid).await {
                            eprintln!("Warning: Failed to stop existing service: {}", e);
                        }
                    }
                } else {
                    // Fallback: check legacy PID file
                    if let Some(pid) = instance::legacy_pid() {
                        if instance::is_process_running(pid) {
                            let _ = stop_service(pid).await;
                        }
                    }
                }
                instance::cleanup_legacy_pid();

                // Start in background
                spawn_background_service(port, cli.config)?;
                tokio::time::sleep(tokio::time::Duration::from_millis(
                    PROCESS_TRANSITION_GRACE_MS,
                ))
                .await;

                let base_url = cli::format_base_url(&config.server.host, effective_port);
                if let Some(pid) = instance::find_instance_pid(&config.server.host, effective_port).await {
                    println!("✅ Grob started in background (PID: {})", pid);
                } else {
                    let _ = poll_health(&base_url, 10, HEALTH_POLL_INTERVAL_MS).await;
                    println!("✅ Grob started in background");
                }
                println!("📡 Running on port {}", effective_port);
                return Ok(());
            }

            // Foreground mode
            let mut config = config;
            if let Some(port) = port {
                config.server.port = port;
            }

            // Check if already running (health-check based)
            if instance::is_instance_running(&config.server.host, config.server.port).await {
                if let Some(pid) = instance::find_instance_pid(&config.server.host, config.server.port).await {
                    eprintln!(
                        "❌ Error: Service is already running (PID: {})",
                        pid
                    );
                } else {
                    eprintln!("❌ Error: Service is already running on port {}", config.server.port);
                }
                eprintln!(
                    "Use 'grob stop' to stop it first, or use 'grob start -d' to restart it"
                );
                return Ok(());
            }
            // Clean up stale legacy PID files
            instance::cleanup_legacy_pid();

            start_foreground(config, config_source).await?;
        }
        Commands::Stop => {
            println!("Stopping Grob...");
            // Try health-check based detection first
            if let Some(pid) = instance::find_instance_pid(&config.server.host, config.server.port).await {
                match stop_service(pid).await {
                    Ok(_) => {
                        println!("✅ Service stopped successfully (PID: {})", pid);
                        instance::cleanup_legacy_pid();
                    }
                    Err(e) => {
                        eprintln!("❌ Failed to stop service (PID: {}): {}", pid, e);
                    }
                }
            } else if let Some(pid) = instance::legacy_pid() {
                // Fallback to legacy PID file
                if instance::is_process_running(pid) {
                    match stop_service(pid).await {
                        Ok(_) => {
                            println!("✅ Service stopped successfully");
                            instance::cleanup_legacy_pid();
                        }
                        Err(e) => {
                            eprintln!("❌ Failed to stop service (PID: {}): {}", pid, e);
                        }
                    }
                } else {
                    println!("Service is not running (stale PID file removed)");
                    instance::cleanup_legacy_pid();
                }
            } else {
                println!("Service is not running");
            }
        }
        Commands::Restart { detach } => {
            // Stop the existing service (health-check based)
            let was_running = if let Some(pid) = instance::find_instance_pid(&config.server.host, config.server.port).await {
                println!("Stopping existing service...");
                match stop_service(pid).await {
                    Ok(_) => true,
                    Err(e) => {
                        eprintln!("Warning: Failed to stop existing service: {}", e);
                        false
                    }
                }
            } else if let Some(pid) = instance::legacy_pid() {
                if instance::is_process_running(pid) {
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
            } else {
                false
            };
            instance::cleanup_legacy_pid();

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
                if let Some(pid) = instance::find_instance_pid(&config.server.host, config.server.port).await {
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
            // Service status
            let (running, pid_info) = if let Some(pid) = instance::find_instance_pid(&config.server.host, config.server.port).await {
                (true, format!(" (PID: {})", pid))
            } else if instance::is_instance_running(&config.server.host, config.server.port).await {
                (true, String::new())
            } else if let Some(pid) = instance::legacy_pid() {
                if instance::is_process_running(pid) {
                    (true, format!(" (PID: {}, legacy)", pid))
                } else {
                    instance::cleanup_legacy_pid();
                    (false, String::new())
                }
            } else {
                (false, String::new())
            };

            if running {
                println!("  Service:   ✅ running{}", pid_info);
            } else {
                println!("  Service:   ❌ stopped");
            }

            // Address
            println!("  Address:   {}", cli::format_bind_addr(&config.server.host, config.server.port));

            // Active preset
            if let Some(ref active) = config.presets.active {
                println!("  Preset:    {}", active);
            }

            // Per-project config
            if let Some(project_path) = cli::find_project_config() {
                println!("  Project:   {}", project_path.display());
            }

            println!();

            // Router
            println!("  Router:");
            println!("    Default:    {}", config.router.default);
            if let Some(ref m) = config.router.think {
                println!("    Think:      {}", m);
            }
            if let Some(ref m) = config.router.background {
                println!("    Background: {}", m);
            }
            if let Some(ref m) = config.router.websearch {
                println!("    WebSearch:  {}", m);
            }

            // GDPR
            if config.router.gdpr {
                let region_info = config.router.region.as_deref().unwrap_or("eu");
                println!("    GDPR:       on (region: {})", region_info);
            }

            println!();

            // Providers
            println!("  Providers:");
            for provider in &config.providers {
                let status = if !provider.is_enabled() {
                    "disabled".to_string()
                } else {
                    let auth_status = match provider.auth_type {
                        providers::AuthType::OAuth => {
                            if let Some(ref oauth_id) = provider.oauth_provider {
                                let oauth_providers = preset::load_oauth_provider_list_pub();
                                if oauth_providers.contains(oauth_id) {
                                    "oauth ok"
                                } else {
                                    "needs auth"
                                }
                            } else {
                                "needs auth"
                            }
                        }
                        providers::AuthType::ApiKey => {
                            if provider.api_key.is_some() {
                                "key set"
                            } else {
                                "no key"
                            }
                        }
                    };
                    let region_tag = provider.region.as_deref().map(|r| format!(" [{}]", r)).unwrap_or_default();
                    format!("{}{}", auth_status, region_tag)
                };
                println!("    {:<20} ({}) {}", provider.name, provider.provider_type, status);
            }

            println!();

            // Models
            println!("  Models ({}):", config.models.len());
            for model in &config.models {
                let providers: Vec<String> = model.mappings.iter()
                    .map(|m| format!("{}/{}", m.provider, m.actual_model))
                    .collect();
                let strategy = model.strategy.label();
                let strategy_tag = if strategy != "fallback" { format!(" [{}]", strategy) } else { String::new() };
                println!("    {:<25} → {}{}", model.name, providers.join(", "), strategy_tag);
            }

            // Spend
            let spend = features::token_pricing::spend::load_spend_data();
            if spend.total > 0.0 || config.budget.monthly_limit_usd > 0.0 {
                println!();
                let budget_limit = config.budget.monthly_limit_usd;
                if budget_limit > 0.0 {
                    let pct = (spend.total / budget_limit) * 100.0;
                    println!(
                        "  Spend:     ${:.2} / ${:.2} ({:.0}%)",
                        spend.total, budget_limit, pct
                    );
                } else {
                    println!("  Spend:     ${:.2} (no budget limit)", spend.total);
                }
            }
        }
        Commands::Spend => {
            let spend = features::token_pricing::spend::load_spend_data();
            let budget = &config.budget;

            // Determine month display name
            let month_display = if let Ok(date) =
                chrono::NaiveDate::parse_from_str(&format!("{}-01", spend.month), "%Y-%m-%d")
            {
                date.format("%B %Y").to_string()
            } else {
                spend.month.clone()
            };

            println!("💰 Spend for {}", month_display);
            println!();

            // Total
            if budget.monthly_limit_usd > 0.0 {
                let pct = if budget.monthly_limit_usd > 0.0 {
                    (spend.total / budget.monthly_limit_usd) * 100.0
                } else {
                    0.0
                };
                println!(
                    "  Total:       ${:.2} / ${:.2} ({:.0}%)",
                    spend.total, budget.monthly_limit_usd, pct
                );
            } else {
                println!("  Total:       ${:.2} (no limit)", spend.total);
            }
            println!();

            // By provider
            if !spend.by_provider.is_empty() {
                println!("  By provider:");
                let mut providers: Vec<_> = spend.by_provider.iter().collect();
                providers.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap());

                for (provider_name, amount) in &providers {
                    // Check if this provider is OAuth (subscription)
                    let is_sub = config
                        .providers
                        .iter()
                        .find(|p| &p.name == *provider_name)
                        .map(|p| p.auth_type == providers::AuthType::OAuth)
                        .unwrap_or(false);

                    // Check provider budget
                    let provider_budget = config
                        .providers
                        .iter()
                        .find(|p| &p.name == *provider_name)
                        .and_then(|p| p.budget_usd);

                    if is_sub {
                        println!("    {:<20} ${:.2} (subscription)", provider_name, amount);
                    } else if let Some(limit) = provider_budget {
                        let pct = (*amount / limit) * 100.0;
                        let flag = if **amount >= limit {
                            " EXCEEDED"
                        } else if pct >= budget.warn_at_percent as f64 {
                            " ⚠️"
                        } else {
                            ""
                        };
                        println!(
                            "    {:<20} ${:.2} / ${:.2} ({:.0}%){}",
                            provider_name, amount, limit, pct, flag
                        );
                    } else {
                        println!("    {:<20} ${:.2}", provider_name, amount);
                    }
                }
                println!();
            }

            // By model
            if !spend.by_model.is_empty() {
                println!("  By model:");
                let mut models: Vec<_> = spend.by_model.iter().collect();
                models.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap());

                for (model_name, amount) in &models {
                    // Check model budget
                    let model_budget = config
                        .models
                        .iter()
                        .find(|m| &m.name == *model_name)
                        .and_then(|m| m.budget_usd);

                    if let Some(limit) = model_budget {
                        let pct = (*amount / limit) * 100.0;
                        let flag = if **amount >= limit {
                            " EXCEEDED"
                        } else if pct >= budget.warn_at_percent as f64 {
                            " ⚠️"
                        } else {
                            ""
                        };
                        println!(
                            "    {:<30} ${:.2} / ${:.2} ({:.0}%){}",
                            model_name, amount, limit, pct, flag
                        );
                    } else {
                        println!("    {:<30} ${:.2}", model_name, amount);
                    }
                }
                println!();
            }

            // Budget remaining
            if budget.monthly_limit_usd > 0.0 {
                let remaining = (budget.monthly_limit_usd - spend.total).max(0.0);
                println!("  Budget remaining: ${:.2} (global)", remaining);
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
                if provider.is_enabled() {
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
            config.server.host = host.unwrap_or_else(|| "::".to_string());

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
        Commands::Exec { port, no_stop, cmd } => {
            let effective_port = port.unwrap_or(config.server.port);
            let base_url = cli::format_base_url(&config.server.host, effective_port);
            let mut we_started = false;

            // 1. Check if Grob is already running (health-check based)
            let already_running = instance::is_instance_running(&config.server.host, effective_port).await;

            if !already_running {
                // 2. Start Grob in background
                eprintln!("Starting Grob on port {}...", effective_port);
                spawn_background_service(Some(effective_port), cli.config.clone())?;

                // 3. Poll /health until ready (max 5s)
                if !poll_health(&base_url, HEALTH_POLL_MAX_ATTEMPTS, HEALTH_POLL_INTERVAL_MS).await
                {
                    eprintln!("❌ Grob failed to start within 5 seconds");
                    std::process::exit(1);
                }
                we_started = true;
                eprintln!("✅ Grob ready on port {}", effective_port);
            }

            // 4. Spawn child process with proxy env vars
            let child_status = {
                let program = &cmd[0];
                let args = &cmd[1..];
                let status = tokio::process::Command::new(program)
                    .args(args)
                    .env("ANTHROPIC_BASE_URL", &base_url)
                    .env("OPENAI_BASE_URL", format!("{}/v1", base_url))
                    .status()
                    .await;

                match status {
                    Ok(s) => s.code().unwrap_or(1),
                    Err(e) => {
                        eprintln!("❌ Failed to run '{}': {}", cmd.join(" "), e);
                        127
                    }
                }
            };

            // 5. Stop Grob if we started it and --no-stop not set
            if we_started && !no_stop {
                if let Some(grob_pid) = instance::find_instance_pid(&config.server.host, effective_port).await {
                    eprintln!("Stopping Grob...");
                    let _ = stop_service(grob_pid).await;
                    instance::cleanup_legacy_pid();
                }
            }

            // 6. Exit with child's exit code
            std::process::exit(child_status);
        }
        Commands::Completions { shell } => {
            let mut cmd = Cli::command();
            generate(shell, &mut cmd, "grob", &mut std::io::stdout());
        }
        Commands::Env => {
            println!("🔑 Environment Variables");
            println!();

            let mut any_missing = false;
            for provider in &config.providers {
                if !provider.is_enabled() {
                    continue;
                }
                // Check if api_key references an env var
                let raw_key = provider.api_key.as_deref().unwrap_or("");
                // At this point env vars are already resolved, so we need to check the original config
                // We detect env var references from the provider_type naming convention
                let env_var_name = format!("{}_API_KEY", provider.name.to_uppercase().replace('-', "_"));

                match provider.auth_type {
                    providers::AuthType::OAuth => {
                        println!("  {:<25} OAuth (no env var needed)", provider.name);
                    }
                    providers::AuthType::ApiKey => {
                        if raw_key.is_empty() {
                            println!("  {:<25} ⚠️  {} MISSING", provider.name, env_var_name);
                            any_missing = true;
                        } else {
                            // Key is set (either literal or resolved env var)
                            println!("  {:<25} ✅ API key configured", provider.name);
                        }
                    }
                }
            }
            if any_missing {
                println!();
                println!("  Hint: export MISSING_VAR=your-key-here");
                println!("  Or:   grob connect <provider>");
            }
        }
        Commands::Connect { provider } => {
            let file_path = match &config_source {
                cli::ConfigSource::File(p) => p.clone(),
                cli::ConfigSource::Url(_) => {
                    eprintln!("❌ Cannot manage credentials for a remote URL config");
                    return Ok(());
                }
            };

            if let Some(ref provider_name) = provider {
                // Single provider mode
                let found = config.providers.iter().any(|p| p.name == *provider_name);
                if !found {
                    eprintln!("❌ Provider '{}' not found in config", provider_name);
                    eprintln!("   Available: {}", config.providers.iter().map(|p| p.name.as_str()).collect::<Vec<_>>().join(", "));
                    return Ok(());
                }
                println!("🔑 Setting up credentials for '{}'...", provider_name);
                if let Err(e) = preset::setup_credentials_interactive_filtered(&file_path, Some(provider_name)) {
                    eprintln!("❌ Credential setup failed: {}", e);
                }
            } else {
                println!("🔑 Setting up credentials for all providers...");
                if let Err(e) = preset::setup_credentials_interactive(&file_path) {
                    eprintln!("❌ Credential setup failed: {}", e);
                }
            }
        }
        Commands::Init => {
            let target = std::env::current_dir()?.join(".grob.toml");
            if target.exists() {
                eprintln!("⚠️  .grob.toml already exists in this directory");
                return Ok(());
            }

            let template = r#"# Per-project Grob configuration overlay
# Values here override the global ~/.grob/config.toml

# Override the default router model for this project
# [router]
# default = "my-project-model"
# think = "my-think-model"
# background = "my-bg-model"
# websearch = "my-ws-model"

# Override budget for this project
# [budget]
# monthly_limit_usd = 50.0

# Add project-specific prompt rules
# [[router.prompt_rules]]
# pattern = "(?i)deploy"
# model = "fast-model"
# strip_match = false

# Override preset
# [presets]
# active = "cheap"
"#;
            std::fs::write(&target, template)?;
            println!("✅ Created .grob.toml in {}", target.display());
            println!("   Edit it to customize Grob for this project.");
        }
        Commands::ConfigDiff { target } => {
            let target_name = target.as_deref().unwrap_or_else(|| {
                config.presets.active.as_deref().unwrap_or("medium")
            });

            // Get preset content
            let preset_content = match preset::get_preset_content(target_name) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("❌ Failed to load target '{}': {}", target_name, e);
                    return Ok(());
                }
            };

            // Parse both configs as TOML values for comparison
            let current_toml = match &config_source {
                cli::ConfigSource::File(p) => {
                    std::fs::read_to_string(p).unwrap_or_default()
                }
                cli::ConfigSource::Url(_) => {
                    eprintln!("❌ Cannot diff remote URL config");
                    return Ok(());
                }
            };

            let current: toml::Value = toml::from_str(&current_toml).unwrap_or(toml::Value::Table(toml::map::Map::new()));
            let preset_val: toml::Value = toml::from_str(&preset_content).unwrap_or(toml::Value::Table(toml::map::Map::new()));

            println!("📋 Config diff: local vs '{}'", target_name);
            println!();

            // Compare key sections
            for section in &["router", "providers", "models"] {
                let local_val = current.get(section);
                let preset_v = preset_val.get(section);
                match (local_val, preset_v) {
                    (Some(l), Some(p)) if l == p => {
                        println!("  [{}]: identical", section);
                    }
                    (Some(_), Some(_)) => {
                        println!("  [{}]: differs", section);
                    }
                    (Some(_), None) => {
                        println!("  [{}]: only in local", section);
                    }
                    (None, Some(_)) => {
                        println!("  [{}]: only in preset", section);
                    }
                    (None, None) => {}
                }
            }
        }
    }

    Ok(())
}

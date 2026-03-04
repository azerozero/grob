use clap::{Parser, Subcommand};
use clap_complete::Shell;

/// Top-level CLI definition with subcommands and global options.
#[derive(Parser)]
#[command(name = "grob")]
#[command(version)]
#[command(before_help = concat!("Grob v", env!("CARGO_PKG_VERSION")))]
#[command(about = "High-performance LLM routing proxy\n\nQuick start:\n  grob exec -- claude     Launch Claude Code through Grob\n  grob exec -- aider      Launch Aider through Grob\n  grob start -d           Start Grob in background\n  grob status             Show service status and models", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Path or URL to configuration file (defaults to ~/.grob/config.toml)
    /// Also settable via GROB_CONFIG env var
    #[arg(short, long, env = "GROB_CONFIG")]
    pub config: Option<String>,

    /// Shorthand: grob -- <cmd> is equivalent to grob exec -- <cmd>
    #[arg(last = true)]
    pub trailing_cmd: Vec<String>,
}

/// Available CLI subcommands for managing the Grob service.
#[derive(Subcommand)]
pub enum Commands {
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
    /// Record & replay sandwich testing harness
    #[cfg(feature = "harness")]
    Harness {
        #[command(subcommand)]
        action: HarnessAction,
    },
}

/// Harness subcommands: record live traffic or replay from a tape file.
#[cfg(feature = "harness")]
#[derive(Subcommand)]
pub enum HarnessAction {
    /// Record HTTP traffic to a tape file (Ctrl+C to stop)
    Record {
        /// Output tape file path (.tape.jsonl)
        #[arg(short, long)]
        output: String,
    },
    /// Replay recorded traffic through grob with a mock backend
    Replay {
        /// Path to the tape file to replay
        #[arg(short, long)]
        tape: std::path::PathBuf,
        /// Grob target URL
        #[arg(short = 'u', long, default_value = "http://[::1]:13456")]
        target: String,
        /// Maximum concurrent requests
        #[arg(short, long, default_value = "10")]
        concurrency: usize,
        /// Target queries per second (0 = unlimited)
        #[arg(short, long, default_value = "0")]
        qps: f64,
        /// Mock backend port (0 = ephemeral)
        #[arg(long, default_value = "0")]
        mock_port: u16,
        /// Mock backend simulated latency in ms
        #[arg(long, default_value = "50")]
        mock_latency_ms: u64,
        /// Fraction of mock responses that return errors (0.0–1.0)
        #[arg(long, default_value = "0.0")]
        error_rate: f64,
        /// Maximum duration in seconds (0 = no limit)
        #[arg(long, default_value = "0")]
        duration: u64,
    },
}

/// Subcommands for managing configuration presets.
#[derive(Subcommand)]
pub enum PresetAction {
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

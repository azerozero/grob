use clap::{Parser, Subcommand};
use clap_complete::Shell;

/// Top-level CLI definition with subcommands and global options.
#[derive(Parser)]
#[command(name = "grob")]
#[command(version)]
#[command(before_help = concat!("Grob v", env!("CARGO_PKG_VERSION")))]
#[command(about = "High-performance LLM routing proxy\n\nQuick start:\n  grob exec -- claude     Launch Claude Code through Grob\n  grob exec -- aider      Launch Aider through Grob\n  grob start -d           Start Grob in background\n  grob status             Show service status and models", long_about = None)]
pub struct Cli {
    /// Subcommand to execute
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Path or URL to configuration file (defaults to ~/.grob/config.toml)
    /// Also settable via GROB_CONFIG env var
    #[arg(short, long, env = "GROB_CONFIG")]
    pub config: Option<String>,
}

/// Known top-level subcommands, used by [`detect_bare_trailing_cmd`] to tell a
/// legitimate `grob exec -- <cmd>` apart from a misuse like `grob -- claude`.
///
/// Kept in sync manually with [`Commands`]. Any new subcommand added to the
/// enum should be appended here so the `grob -- <cmd>` guard keeps working.
const KNOWN_SUBCOMMANDS: &[&str] = &[
    "start",
    "stop",
    "restart",
    "status",
    "spend",
    "model",
    "validate",
    "preset",
    "run",
    "exec",
    "launch", // alias of exec
    "completions",
    "setup-completions",
    "env",
    "connect",
    "init",
    "config-diff",
    "setup",
    "watch",
    "key",
    "rollback",
    "bench",
    "doctor",
    "upgrade",
    "harness",
    "help",
];

/// Detects the `grob -- <cmd>` misuse and returns the suggested replacement.
///
/// Returns `Some("grob exec -- <cmd>")` when the argv looks like a bare
/// `--` escape hatch without a subcommand (`grob -- claude --print hi`),
/// so `main.rs` can print a hint and exit non-zero instead of letting
/// clap emit a generic `unexpected argument` error.
///
/// # Examples
///
/// ```
/// use grob::cli::args::detect_bare_trailing_cmd;
///
/// let bare = vec!["grob".into(), "--".into(), "claude".into()];
/// assert_eq!(
///     detect_bare_trailing_cmd(&bare).as_deref(),
///     Some("grob exec -- claude"),
/// );
///
/// let ok = vec!["grob".into(), "exec".into(), "--".into(), "claude".into()];
/// assert!(detect_bare_trailing_cmd(&ok).is_none());
/// ```
#[must_use]
pub fn detect_bare_trailing_cmd(args: &[String]) -> Option<String> {
    let mut iter = args.iter().enumerate().skip(1);
    while let Some((idx, arg)) = iter.next() {
        if arg == "--" {
            // Bare `--` found with no subcommand before it.
            let trailing: Vec<&str> = args[idx + 1..].iter().map(String::as_str).collect();
            if trailing.is_empty() {
                return None;
            }
            return Some(format!("grob exec -- {}", trailing.join(" ")));
        }
        // Skip global flags (and their values) that can legitimately
        // appear before the subcommand.
        if arg == "-c" || arg == "--config" {
            iter.next(); // consume the value
            continue;
        }
        if arg.starts_with('-') {
            // Any other flag : skip it, do not treat it as a subcommand.
            continue;
        }
        if KNOWN_SUBCOMMANDS.contains(&arg.as_str()) {
            // A real subcommand came first : hand off to clap.
            return None;
        }
        // Unknown positional argument : clap will reject it with its
        // own error, no need to short-circuit.
        return None;
    }
    None
}

/// Available CLI subcommands for managing the Grob service.
#[derive(Subcommand)]
pub enum Commands {
    /// Start the router service
    Start {
        /// Override the listening port
        #[arg(short, long)]
        port: Option<u16>,
        /// Run as a background daemon
        #[arg(short = 'd', long)]
        detach: bool,
    },
    /// Stop the router service
    Stop,
    /// Restart the router service
    Restart {
        /// Run as a background daemon after restart
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
        /// Preset management subcommand
        #[command(subcommand)]
        action: PresetAction,
    },
    /// Run in container mode (foreground, 0.0.0.0, JSON logs, graceful shutdown, no PID file)
    Run {
        /// Override the listening port (env: GROB_PORT)
        #[arg(short, long, env = "GROB_PORT")]
        port: Option<u16>,
        /// Override the bind host address (env: GROB_HOST)
        #[arg(long, env = "GROB_HOST")]
        host: Option<String>,
        /// Override the log level (env: GROB_LOG_LEVEL)
        #[arg(long, env = "GROB_LOG_LEVEL")]
        log_level: Option<String>,
        /// Emit structured JSON logs instead of human-readable
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
        /// Override the listening port
        #[arg(short, long)]
        port: Option<u16>,
        /// Keep Grob running after the child command exits
        #[arg(long)]
        no_stop: bool,
        /// Command and arguments to execute behind the proxy
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
    /// Generate shell completions
    ///
    /// Output completions for the given shell to stdout.
    /// Example: grob completions zsh > ~/.zfunc/_grob
    Completions {
        /// Target shell for completion script output
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
    Connect {
        /// Specific provider name to configure (all if omitted)
        provider: Option<String>,
    },
    /// Initialize a per-project .grob.toml in the current directory
    Init,
    /// Compare local config against a preset or remote config
    ConfigDiff {
        /// Preset name or URL to compare against current config
        target: Option<String>,
    },
    /// Interactive setup wizard (auto-triggered on first run)
    Setup {
        /// Accept all defaults without prompting
        #[arg(long)]
        yes: bool,
        /// Preview changes without writing to disk
        #[arg(long)]
        dry_run: bool,
    },
    /// Live traffic inspector — watch requests, DLP actions, and fallbacks in real time
    #[cfg(feature = "watch")]
    Watch,
    /// Manage virtual API keys (create, list, revoke)
    Key {
        /// Key management subcommand
        #[command(subcommand)]
        action: KeyAction,
    },
    /// Restore previous configuration from backup
    Rollback,
    /// Run performance benchmark on the current system
    Bench {
        /// Number of requests per scenario (default: 500, used in sequential mode)
        #[arg(short = 'n', long, default_value = "500")]
        requests: usize,
        /// Include auth overhead (creates a virtual key and authenticates each request)
        #[arg(long)]
        with_auth: bool,
        /// Output format (table or json)
        #[arg(long, default_value = "table")]
        format: String,
        /// Concurrent requests (0 = auto = num_cpus, 1 = sequential)
        #[arg(short, long, default_value = "1")]
        concurrency: usize,
        /// Payload size: small (~300B), medium (~80KB), large (~150KB), all
        #[arg(short, long, default_value = "small")]
        payload: String,
        /// Run escalation mode: test each feature layer incrementally
        #[arg(long)]
        escalate: bool,
    },
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
        /// Harness subcommand (record or replay)
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

/// Subcommands for managing virtual API keys.
#[derive(Subcommand)]
pub enum KeyAction {
    /// Create a new virtual API key
    Create {
        /// Human-readable key name
        #[arg(short, long)]
        name: String,
        /// Tenant identifier
        #[arg(short, long)]
        tenant: String,
        /// Monthly budget in USD (optional)
        #[arg(short, long)]
        budget: Option<f64>,
        /// Rate limit in requests per second (optional)
        #[arg(short, long)]
        rate_limit: Option<u32>,
        /// Comma-separated list of allowed model names (optional)
        #[arg(short, long, value_delimiter = ',')]
        allowed_models: Option<Vec<String>>,
        /// Key expiration in days from now (optional)
        #[arg(short, long)]
        expires: Option<u64>,
    },
    /// List all virtual API keys
    List {
        /// Output in JSON format instead of table
        #[arg(long)]
        json: bool,
    },
    /// Revoke a virtual API key by ID or prefix
    Revoke {
        /// Key UUID or prefix to revoke
        id_or_prefix: String,
    },
}

/// Subcommands for managing configuration presets.
#[derive(Subcommand)]
pub enum PresetAction {
    /// List available presets
    List,
    /// Show detailed info about a preset (providers, models, env vars)
    Info {
        /// Preset name to inspect
        name: String,
    },
    /// Install presets from a git repo or local path
    Install {
        /// Git repo URL or local directory path
        source: String,
    },
    /// Apply a preset to config (backs up current config)
    Apply {
        /// Preset name to apply
        name: String,
        /// Hot-reload the running server after applying
        #[arg(short, long)]
        reload: bool,
        /// Preview changes without writing to disk
        #[arg(long)]
        dry_run: bool,
    },
    /// Export current config as a reusable preset
    Export {
        /// Name for the exported preset
        name: String,
        /// Optional environment tag (e.g., "qa", "prod") — saves as {name}.{env}.toml
        #[arg(long)]
        env: Option<String>,
    },
    /// Sync presets from configured git repo
    Sync,
    /// Push a preset to a remote grob instance
    Push {
        /// Preset name to push
        name: String,
        /// Target grob instance URL (e.g., https://grob-qa.example.com)
        #[arg(long)]
        target: String,
        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
    },
    /// Pull config from a remote grob instance and save as a preset
    Pull {
        /// Source grob instance URL (e.g., https://grob-prod.example.com)
        #[arg(long)]
        from: String,
        /// Name to save the pulled config as
        #[arg(long)]
        save: String,
    },
}

#[cfg(test)]
mod tests {
    use super::detect_bare_trailing_cmd;

    fn args(raw: &[&str]) -> Vec<String> {
        raw.iter().map(|s| (*s).to_string()).collect()
    }

    /// W-4 : `grob -- claude` → hint `grob exec -- claude`.
    #[test]
    fn test_w4_detect_bare_trailing_simple() {
        insta::assert_snapshot!(
            detect_bare_trailing_cmd(&args(&["grob", "--", "claude"]))
                .expect("bare `--` should be detected"),
            @"grob exec -- claude"
        );
    }

    /// W-4 : le hint propage les arguments du binaire cible.
    #[test]
    fn test_w4_detect_bare_trailing_with_args() {
        insta::assert_snapshot!(
            detect_bare_trailing_cmd(&args(&[
                "grob", "--", "claude", "--print", "hello world",
            ]))
            .expect("bare `--` should be detected"),
            @"grob exec -- claude --print hello world"
        );
    }

    /// W-4 : `grob -c cfg.toml -- claude` -> flag global ignore, hint quand meme.
    #[test]
    fn test_w4_detect_bare_trailing_after_config_flag() {
        assert_eq!(
            detect_bare_trailing_cmd(&args(&["grob", "-c", "/tmp/cfg.toml", "--", "claude",])),
            Some("grob exec -- claude".to_string())
        );
    }

    /// W-4 : forme correcte `grob exec -- claude` = aucun hint.
    #[test]
    fn test_w4_detect_bare_trailing_ignores_exec() {
        assert_eq!(
            detect_bare_trailing_cmd(&args(&["grob", "exec", "--", "claude"])),
            None
        );
    }

    /// W-4 : alias `launch` = aucun hint (exec alias).
    #[test]
    fn test_w4_detect_bare_trailing_ignores_launch_alias() {
        assert_eq!(
            detect_bare_trailing_cmd(&args(&["grob", "launch", "--", "aider"])),
            None
        );
    }

    /// W-4 : aucun `--` = aucun hint.
    #[test]
    fn test_w4_detect_bare_trailing_no_dashdash() {
        assert_eq!(detect_bare_trailing_cmd(&args(&["grob", "status"])), None);
    }

    /// W-4 : `grob --` sans rien apres = aucun hint (rien a executer).
    #[test]
    fn test_w4_detect_bare_trailing_empty_tail() {
        assert_eq!(detect_bare_trailing_cmd(&args(&["grob", "--"])), None);
    }

    /// W-4 : positional inconnu avant `--` = on laisse clap gerer l'erreur.
    #[test]
    fn test_w4_detect_bare_trailing_unknown_positional() {
        assert_eq!(
            detect_bare_trailing_cmd(&args(&["grob", "foobar", "--", "claude"])),
            None
        );
    }
}

use std::process::Command;

/// Grace period in milliseconds after stopping a process before continuing.
pub const PROCESS_TRANSITION_GRACE_MS: u64 = 500;
/// Interval in milliseconds between consecutive health poll attempts.
pub const HEALTH_POLL_INTERVAL_MS: u64 = 100;
/// Maximum number of health poll attempts before declaring failure.
pub const HEALTH_POLL_MAX_ATTEMPTS: u32 = 50; // 50 * 100ms = 5s max

/// Sends a 2-second GET to `{base_url}/health`; returns `true` only for a 2xx response.
pub async fn is_grob_healthy(base_url: &str) -> bool {
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

/// Polls the health endpoint repeatedly until success or exhaustion.
pub async fn poll_health(base_url: &str, max_attempts: u32, interval_ms: u64) -> bool {
    for _ in 0..max_attempts {
        if is_grob_healthy(base_url).await {
            return true;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(interval_ms)).await;
    }
    false
}

/// Sends SIGTERM to the given process and waits until it exits (up to 5s).
#[cfg(feature = "unix-signals")]
pub async fn stop_service(pid: u32) -> anyhow::Result<()> {
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;
    if !crate::shared::pid::is_process_running(pid) {
        anyhow::bail!("refusing to stop PID {}: not a running Grob process", pid);
    }

    let nix_pid = Pid::from_raw(pid as i32);
    kill(nix_pid, Signal::SIGTERM).map_err(|e| anyhow::anyhow!("Failed to stop service: {}", e))?;

    // Wait for the process to actually exit (not just grace period).
    // Check every 100ms for up to 5 seconds.
    for _ in 0..50 {
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        if !crate::shared::pid::is_process_running(pid) {
            // Process is gone, or the PID was reused by a non-Grob process.
            return Ok(());
        }
    }

    // Still alive after 5s — send SIGKILL as last resort.
    tracing::warn!(
        "Process {} did not exit after SIGTERM, sending SIGKILL",
        pid
    );
    if crate::shared::pid::is_process_running(pid) {
        kill(nix_pid, Signal::SIGKILL)
            .map_err(|e| anyhow::anyhow!("Failed to force stop service: {}", e))?;
    }
    tokio::time::sleep(tokio::time::Duration::from_millis(
        PROCESS_TRANSITION_GRACE_MS,
    ))
    .await;
    if crate::shared::pid::is_process_running(pid) {
        anyhow::bail!("service PID {} is still running after SIGKILL", pid);
    }
    Ok(())
}

/// Fallback when unix-signals is unavailable (non-unix platforms).
#[cfg(all(unix, not(feature = "unix-signals")))]
pub async fn stop_service(_pid: u32) -> anyhow::Result<()> {
    anyhow::bail!("stop_service is not supported without unix-signals feature")
}

/// Terminates the given process via `taskkill` and waits for the grace period.
#[cfg(windows)]
pub async fn stop_service(pid: u32) -> anyhow::Result<()> {
    let output = std::process::Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/F"])
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to run taskkill: {}", e))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Failed to stop service (PID {}): {}", pid, stderr.trim());
    }
    tokio::time::sleep(tokio::time::Duration::from_millis(
        PROCESS_TRANSITION_GRACE_MS,
    ))
    .await;
    Ok(())
}

/// Starts the Grob server in the foreground, writing the PID file and handling SIGTERM for graceful shutdown.
pub async fn start_foreground(
    config: crate::config::AppConfig,
    config_source: crate::cli::ConfigSource,
) -> anyhow::Result<()> {
    if let Err(e) = crate::shared::pid::write_pid() {
        eprintln!("Warning: Failed to write PID file: {}", e);
    }

    tracing::info!("Starting Grob on port {}", config.server.port);
    println!("🚀 Grob v{}", env!("CARGO_PKG_VERSION"));
    println!(
        "📡 Starting server on {}",
        crate::cli::format_bind_addr(&config.server.host, config.server.port.value())
    );
    println!();

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

    let shutdown = async {
        let ctrl_c = tokio::signal::ctrl_c();
        #[cfg(unix)]
        {
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("failed to register SIGTERM handler");
            let mut sigusr1 =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())
                    .expect("failed to register SIGUSR1 handler");
            tokio::select! {
                _ = ctrl_c => { tracing::info!("Received SIGINT, shutting down..."); }
                _ = sigterm.recv() => { tracing::info!("Received SIGTERM, shutting down..."); }
                _ = sigusr1.recv() => { tracing::info!("Received SIGUSR1 (hot restart), draining..."); }
            }
        }
        #[cfg(not(unix))]
        {
            ctrl_c.await.ok();
            tracing::info!("Received SIGINT, shutting down...");
        }
    };

    let result = crate::server::start_server(config, config_source, shutdown).await;
    let _ = crate::shared::pid::cleanup_pid_if_current();
    result
}

/// Returns the path of the detached daemon log file (`~/.grob/grob.log`).
pub fn daemon_log_path() -> Option<std::path::PathBuf> {
    crate::grob_home().map(|h| h.join("grob.log"))
}

/// Builds the argument vector for the detached daemon, in clap-acceptable order.
///
/// `-c/--config` is a global flag on the top-level [`crate::cli::args::Cli`], not
/// on the `start` subcommand, so clap only accepts it *before* the subcommand —
/// emitting it after `start` makes the child abort with "unexpected argument
/// '--config'" and the daemon never binds. The order is therefore: global flags,
/// subcommand, then subcommand flags (`--port`). Returning the args as a vector
/// keeps this ordering unit-testable without spawning a process.
fn daemon_command_args(
    port: Option<u16>,
    config: Option<String>,
    hot_upgrade: bool,
    adopt_from_system: bool,
) -> Vec<String> {
    let mut args = Vec::new();
    if let Some(config) = config {
        args.push("--config".to_string());
        args.push(config);
    }
    args.push("start".to_string());
    if let Some(port) = port {
        args.push("--port".to_string());
        args.push(port.to_string());
    }
    if hot_upgrade {
        args.push("--hot-upgrade".to_string());
    }
    if adopt_from_system {
        args.push("--adopt-from-system".to_string());
    }
    args
}

/// Spawns the Grob server as a detached background process.
///
/// The child's stdout and stderr are redirected to `~/.grob/grob.log` (append
/// mode) so a crash in detached mode leaves a diagnosable trail instead of
/// vanishing into `/dev/null`. Returns the log path on success, or `None` when
/// the log file could not be opened (in which case output is discarded).
pub fn spawn_background_service(
    port: Option<u16>,
    config: Option<String>,
    adopt_from_system: bool,
) -> anyhow::Result<Option<std::path::PathBuf>> {
    spawn_background_service_with_mode(port, config, false, adopt_from_system)
}

/// Spawns a detached daemon for zero-downtime upgrade.
///
/// The upgraded daemon re-reads the config file, so credential adoption
/// follows `[auth] adopt_from_system` rather than any per-invocation flag.
pub fn spawn_upgrade_background_service(
    port: Option<u16>,
    config: Option<String>,
) -> anyhow::Result<Option<std::path::PathBuf>> {
    spawn_background_service_with_mode(port, config, true, false)
}

fn spawn_background_service_with_mode(
    port: Option<u16>,
    config: Option<String>,
    hot_upgrade: bool,
    adopt_from_system: bool,
) -> anyhow::Result<Option<std::path::PathBuf>> {
    use std::process::Stdio;

    let exe_path = std::env::current_exe()?;
    let mut cmd = Command::new(&exe_path);
    cmd.args(daemon_command_args(
        port,
        config,
        hot_upgrade,
        adopt_from_system,
    ));

    #[cfg(all(unix, feature = "unix-signals"))]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: setsid() is async-signal-safe and called in pre_exec (after fork,
        // before exec) where only one thread exists in the child process.
        #[allow(unsafe_code)]
        unsafe {
            cmd.pre_exec(|| {
                nix::libc::setsid();
                Ok(())
            });
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // DETACHED_PROCESS (0x08) + CREATE_NEW_PROCESS_GROUP (0x200)
        cmd.creation_flags(0x0000_0008 | 0x0000_0200);
    }

    // Capture daemon output to a log file so detached crashes are visible.
    let log_path = daemon_log_path();
    let log_file = log_path.as_ref().and_then(|path| {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .ok()
    });

    cmd.stdin(Stdio::null());
    let captured = match log_file {
        Some(file) => {
            let err = file
                .try_clone()
                .map_err(|e| anyhow::anyhow!("Failed to duplicate log file handle: {}", e))?;
            cmd.stdout(Stdio::from(file)).stderr(Stdio::from(err));
            true
        }
        None => {
            cmd.stdout(Stdio::null()).stderr(Stdio::null());
            false
        }
    };

    cmd.spawn()?;
    Ok(if captured { log_path } else { None })
}

#[cfg(test)]
mod tests {
    use super::daemon_command_args;
    use crate::cli::args::{Cli, Commands};
    use clap::Parser;

    /// Re-parses the daemon args through clap to prove the child can start.
    ///
    /// This is the exact failure mode of the original bug: `--config` was
    /// emitted after `start`, which clap rejects because `config` is a global
    /// flag on the top-level [`Cli`], not on the `start` subcommand.
    fn parse(args: &[String]) -> Cli {
        let argv = std::iter::once("grob".to_string()).chain(args.iter().cloned());
        Cli::try_parse_from(argv).expect("daemon args must parse as a valid grob invocation")
    }

    #[test]
    fn daemon_args_with_config_parse_back_into_clap() {
        let args = daemon_command_args(
            Some(13456),
            Some("/tmp/grob.toml".to_string()),
            false,
            false,
        );

        // The global flag must precede the subcommand.
        let start_idx = args.iter().position(|a| a == "start").unwrap();
        let config_idx = args.iter().position(|a| a == "--config").unwrap();
        assert!(
            config_idx < start_idx,
            "--config must come before the start subcommand, got {args:?}"
        );

        let cli = parse(&args);
        assert_eq!(cli.config.as_deref(), Some("/tmp/grob.toml"));
        assert!(matches!(
            cli.command,
            Some(Commands::Start {
                port: Some(13456),
                detach: false,
                hot_upgrade: false,
                adopt_from_system: false
            })
        ));
    }

    #[test]
    fn daemon_args_without_config_parse_back_into_clap() {
        let args = daemon_command_args(None, None, false, false);
        let cli = parse(&args);
        assert_eq!(cli.config, None);
        assert!(matches!(
            cli.command,
            Some(Commands::Start { port: None, .. })
        ));
    }

    #[test]
    fn daemon_args_forward_adopt_from_system_to_the_child() {
        let args = daemon_command_args(None, None, false, true);
        let cli = parse(&args);
        assert!(matches!(
            cli.command,
            Some(Commands::Start {
                adopt_from_system: true,
                ..
            })
        ));
    }

    #[test]
    fn daemon_args_for_upgrade_parse_with_hot_upgrade_flag() {
        let args =
            daemon_command_args(Some(13456), Some("/tmp/grob.toml".to_string()), true, false);
        assert!(args.iter().any(|arg| arg == "--hot-upgrade"));

        let cli = parse(&args);
        assert_eq!(cli.config.as_deref(), Some("/tmp/grob.toml"));
        assert!(matches!(
            cli.command,
            Some(Commands::Start {
                port: Some(13456),
                detach: false,
                hot_upgrade: true,
                adopt_from_system: false
            })
        ));
    }
}

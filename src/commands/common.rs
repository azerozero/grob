use std::process::Command;

/// Grace period in milliseconds after stopping a process before continuing.
pub const PROCESS_TRANSITION_GRACE_MS: u64 = 500;
/// Interval in milliseconds between consecutive health poll attempts.
pub const HEALTH_POLL_INTERVAL_MS: u64 = 100;
/// Maximum number of health poll attempts before declaring failure.
pub const HEALTH_POLL_MAX_ATTEMPTS: u32 = 50; // 50 * 100ms = 5s max

/// Checks whether the Grob service at the given URL is healthy.
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
    let nix_pid = Pid::from_raw(pid as i32);
    kill(nix_pid, Signal::SIGTERM).map_err(|e| anyhow::anyhow!("Failed to stop service: {}", e))?;

    // Wait for the process to actually exit (not just grace period).
    // Check every 100ms for up to 5 seconds.
    for _ in 0..50 {
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        if kill(nix_pid, None).is_err() {
            // Process is gone — signal 0 failed means PID doesn't exist.
            return Ok(());
        }
    }

    // Still alive after 5s — send SIGKILL as last resort.
    tracing::warn!(
        "Process {} did not exit after SIGTERM, sending SIGKILL",
        pid
    );
    let _ = kill(nix_pid, Signal::SIGKILL);
    tokio::time::sleep(tokio::time::Duration::from_millis(
        PROCESS_TRANSITION_GRACE_MS,
    ))
    .await;
    Ok(())
}

/// Fallback when unix-signals is unavailable (unikernel or non-unix).
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

/// Starts the Grob server in the foreground with signal handling.
pub async fn start_foreground(
    config: crate::cli::AppConfig,
    config_source: crate::cli::ConfigSource,
) -> anyhow::Result<()> {
    if let Err(e) = crate::pid::write_pid() {
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
    let _ = crate::pid::cleanup_pid();
    result
}

/// Spawns the Grob server as a detached background process.
pub fn spawn_background_service(port: Option<u16>, config: Option<String>) -> anyhow::Result<()> {
    let exe_path = std::env::current_exe()?;
    let mut cmd = Command::new(&exe_path);
    cmd.arg("start");

    if let Some(port) = port {
        cmd.arg("--port").arg(port.to_string());
    }
    if let Some(config) = config {
        cmd.arg("--config").arg(config);
    }

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

    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    cmd.spawn()?;
    Ok(())
}

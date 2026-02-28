use std::process::Command;

pub const PROCESS_TRANSITION_GRACE_MS: u64 = 500;
pub const HEALTH_POLL_INTERVAL_MS: u64 = 100;
pub const HEALTH_POLL_MAX_ATTEMPTS: u32 = 50; // 50 * 100ms = 5s max

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

pub async fn poll_health(base_url: &str, max_attempts: u32, interval_ms: u64) -> bool {
    for _ in 0..max_attempts {
        if is_grob_healthy(base_url).await {
            return true;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(interval_ms)).await;
    }
    false
}

pub async fn stop_service(pid: u32) -> anyhow::Result<()> {
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
        crate::cli::format_bind_addr(&config.server.host, config.server.port)
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

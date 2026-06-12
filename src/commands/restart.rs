use super::common::*;
use crate::cli;
use crate::shared::instance;

/// Stops any running instance and restarts the Grob service.
pub async fn cmd_restart(
    config: cli::AppConfig,
    config_source: cli::ConfigSource,
    detach: bool,
    cli_config: Option<String>,
) -> anyhow::Result<()> {
    let was_running = if let Some(pid) =
        instance::find_instance_pid(&config.server.host, config.server.port.value()).await
    {
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
        println!("Starting service in background...");
        let port_from_config = Some(config.server.port.value());
        // Restart is config-driven: credential adoption follows the config
        // file, not a remembered per-invocation flag.
        let log_path = spawn_background_service(port_from_config, cli_config, false)?;
        let base_url = cli::format_base_url(&config.server.host, config.server.port.value());

        let verb = if was_running { "restarted" } else { "started" };
        // Confirm the listener is actually serving before reporting success.
        if poll_health(&base_url, HEALTH_POLL_MAX_ATTEMPTS, HEALTH_POLL_INTERVAL_MS).await {
            match instance::find_instance_pid(&config.server.host, config.server.port.value()).await
            {
                Some(pid) => println!("✅ Service {} successfully (PID: {})", verb, pid),
                None => println!("✅ Service {} successfully", verb),
            }
            if let Some(ref path) = log_path {
                println!("📝 Logs: {}", path.display());
            }
        } else {
            let timeout_secs = HEALTH_POLL_MAX_ATTEMPTS as u64 * HEALTH_POLL_INTERVAL_MS / 1000;
            eprintln!(
                "❌ Service did not become healthy within {}s.",
                timeout_secs
            );
            match log_path {
                Some(path) => eprintln!("   Check the daemon log: {}", path.display()),
                None => eprintln!("   No log file available (could not open ~/.grob/grob.log)."),
            }
            anyhow::bail!("service failed to restart");
        }
    } else {
        start_foreground(config, config_source).await?;
    }
    Ok(())
}

use super::common::*;
use crate::{cli, instance};

pub async fn cmd_start(
    config: cli::AppConfig,
    config_source: cli::ConfigSource,
    port: Option<u16>,
    detach: bool,
    cli_config: Option<String>,
) -> anyhow::Result<()> {
    let effective_port = port.unwrap_or(config.server.port);

    if detach {
        println!("Starting Grob in background...");

        if instance::is_instance_running(&config.server.host, effective_port).await {
            println!("Stopping existing service...");
            if let Some(pid) =
                instance::find_instance_pid(&config.server.host, effective_port).await
            {
                if let Err(e) = stop_service(pid).await {
                    eprintln!("Warning: Failed to stop existing service: {}", e);
                }
            }
        } else if let Some(pid) = instance::legacy_pid() {
            if instance::is_process_running(pid) {
                let _ = stop_service(pid).await;
            }
        }
        instance::cleanup_legacy_pid();

        spawn_background_service(port, cli_config)?;
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

    if instance::is_instance_running(&config.server.host, config.server.port).await {
        if let Some(pid) =
            instance::find_instance_pid(&config.server.host, config.server.port).await
        {
            eprintln!("❌ Error: Service is already running (PID: {})", pid);
        } else {
            eprintln!(
                "❌ Error: Service is already running on port {}",
                config.server.port
            );
        }
        eprintln!("Use 'grob stop' to stop it first, or use 'grob start -d' to restart it");
        return Ok(());
    }
    instance::cleanup_legacy_pid();

    start_foreground(config, config_source).await?;
    Ok(())
}

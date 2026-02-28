use super::common::*;
use crate::{cli, instance};

pub async fn cmd_restart(
    config: cli::AppConfig,
    config_source: cli::ConfigSource,
    detach: bool,
    cli_config: Option<String>,
) -> anyhow::Result<()> {
    let was_running = if let Some(pid) =
        instance::find_instance_pid(&config.server.host, config.server.port).await
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
        let port_from_config = Some(config.server.port);
        spawn_background_service(port_from_config, cli_config)?;
        tokio::time::sleep(tokio::time::Duration::from_millis(
            PROCESS_TRANSITION_GRACE_MS,
        ))
        .await;

        let verb = if was_running { "restarted" } else { "started" };
        if let Some(pid) =
            instance::find_instance_pid(&config.server.host, config.server.port).await
        {
            println!("✅ Service {} successfully (PID: {})", verb, pid);
        } else {
            println!("✅ Service {} successfully", verb);
        }
    } else {
        start_foreground(config, config_source).await?;
    }
    Ok(())
}

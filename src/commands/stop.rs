use super::common::*;
use crate::{cli, instance};

/// Stops the running Grob service by PID and cleans up stale state.
///
/// Checks both the health-based instance detection and the PID file.
/// Waits for the process to fully exit before returning (prevents db lock issues).
pub async fn cmd_stop(config: &cli::AppConfig) -> anyhow::Result<()> {
    println!("Stopping Grob...");
    let mut stopped = false;

    if let Some(pid) =
        instance::find_instance_pid(&config.server.host, config.server.port.value()).await
    {
        match stop_service(pid).await {
            Ok(_) => {
                println!("✅ Service stopped successfully (PID: {})", pid);
                stopped = true;
            }
            Err(e) => {
                eprintln!("❌ Failed to stop service (PID: {}): {}", pid, e);
            }
        }
    }

    if let Some(pid) = instance::legacy_pid() {
        if instance::is_process_running(pid) && !stopped {
            match stop_service(pid).await {
                Ok(_) => {
                    println!("✅ Service stopped successfully (PID: {})", pid);
                    stopped = true;
                }
                Err(e) => {
                    eprintln!("❌ Failed to stop service (PID: {}): {}", pid, e);
                }
            }
        }
    }

    // Always clean up PID file.
    instance::cleanup_legacy_pid();

    if !stopped {
        println!("Service is not running");
    }

    Ok(())
}

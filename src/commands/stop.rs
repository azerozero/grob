use super::common::*;
use crate::{cli, instance};

pub async fn cmd_stop(config: &cli::AppConfig) -> anyhow::Result<()> {
    println!("Stopping Grob...");
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
    Ok(())
}

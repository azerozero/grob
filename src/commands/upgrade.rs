use super::common::*;
use crate::{cli, instance, pid};

pub async fn cmd_upgrade(
    config: &cli::AppConfig,
    cli_config: Option<String>,
) -> anyhow::Result<()> {
    let base_url = cli::format_base_url(&config.server.host, config.server.port);

    let old_pid = match instance::find_instance_pid(&config.server.host, config.server.port).await {
        Some(pid) => pid,
        None => {
            eprintln!(
                "❌ No running Grob instance found on port {}",
                config.server.port
            );
            eprintln!("   Start one first with: grob start -d");
            return Ok(());
        }
    };
    println!("🔄 Upgrading Grob (old PID: {})...", old_pid);

    spawn_background_service(Some(config.server.port), cli_config)?;
    println!("   Spawned new process, waiting for health...");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(35);
    let new_pid = loop {
        if std::time::Instant::now() > deadline {
            eprintln!("❌ Timeout waiting for new process to become healthy");
            return Ok(());
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(HEALTH_POLL_INTERVAL_MS)).await;

        let url = format!("{}/health", base_url);
        if let Ok(resp) = reqwest::Client::new()
            .get(&url)
            .timeout(std::time::Duration::from_secs(2))
            .send()
            .await
        {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                if let Some(pid_val) = json.get("pid").and_then(|v| v.as_u64()) {
                    let pid_val = pid_val as u32;
                    if pid_val != old_pid {
                        break pid_val;
                    }
                }
            }
        }
    };
    println!("   New process healthy (PID: {})", new_pid);

    #[cfg(unix)]
    {
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid;
        println!("   Sending SIGUSR1 to old process (PID: {})...", old_pid);
        if let Err(e) = kill(Pid::from_raw(old_pid as i32), Signal::SIGUSR1) {
            eprintln!("   Warning: Failed to signal old process: {}", e);
        }
    }

    let drain_deadline = std::time::Instant::now() + std::time::Duration::from_secs(35);
    loop {
        if !pid::is_process_running(old_pid) {
            println!("   Old process (PID: {}) exited", old_pid);
            break;
        }
        if std::time::Instant::now() > drain_deadline {
            eprintln!("   Warning: Old process still running after 35s drain timeout");
            break;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
    }

    println!("✅ Upgrade complete! New PID: {}", new_pid);
    Ok(())
}

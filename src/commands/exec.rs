use super::common::*;
use crate::{cli, instance};

pub async fn cmd_exec(
    config: &cli::AppConfig,
    port: Option<u16>,
    no_stop: bool,
    cmd: Vec<String>,
    cli_config: Option<String>,
) -> anyhow::Result<()> {
    let effective_port = port.unwrap_or(config.server.port);
    let base_url = cli::format_base_url(&config.server.host, effective_port);
    let mut we_started = false;

    let already_running = instance::is_instance_running(&config.server.host, effective_port).await;

    if !already_running {
        eprintln!("Starting Grob on port {}...", effective_port);
        spawn_background_service(Some(effective_port), cli_config)?;

        if !poll_health(&base_url, HEALTH_POLL_MAX_ATTEMPTS, HEALTH_POLL_INTERVAL_MS).await {
            eprintln!("❌ Grob failed to start within 5 seconds");
            std::process::exit(1);
        }
        we_started = true;
        eprintln!("✅ Grob ready on port {}", effective_port);
    }

    let child_status = {
        let program = &cmd[0];
        let args = &cmd[1..];
        let status = tokio::process::Command::new(program)
            .args(args)
            .env("ANTHROPIC_BASE_URL", &base_url)
            .env("OPENAI_BASE_URL", format!("{}/v1", base_url))
            .status()
            .await;

        match status {
            Ok(s) => s.code().unwrap_or(1),
            Err(e) => {
                eprintln!("❌ Failed to run '{}': {}", cmd.join(" "), e);
                127
            }
        }
    };

    if we_started && !no_stop {
        if let Some(grob_pid) =
            instance::find_instance_pid(&config.server.host, effective_port).await
        {
            eprintln!("Stopping Grob...");
            let _ = stop_service(grob_pid).await;
            instance::cleanup_legacy_pid();
        }
    }

    std::process::exit(child_status);
}

use super::common::*;
use crate::cli;
use crate::shared::instance;

/// Runs a command with Grob as the LLM proxy, auto-starting if needed.
pub async fn cmd_exec(
    config: &cli::AppConfig,
    port: Option<u16>,
    no_stop: bool,
    cmd: Vec<String>,
    cli_config: Option<String>,
) -> anyhow::Result<()> {
    let effective_port = port.unwrap_or(config.server.port.value());
    let base_url = cli::format_base_url(&config.server.host, effective_port);
    let mut we_started = false;

    let already_running = instance::is_instance_running(&config.server.host, effective_port).await;

    if !already_running {
        // Pre-flight credential check before spawning background service.
        if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
            if let Ok(store) =
                crate::storage::GrobStore::open(&crate::storage::GrobStore::default_path())
            {
                let store = std::sync::Arc::new(store);
                if let Ok(token_store) = crate::auth::TokenStore::with_store(store) {
                    let statuses =
                        crate::auth::auto_flow::detect_credentials(&config.providers, &token_store);
                    let has_missing = statuses
                        .iter()
                        .any(|s| !matches!(s, crate::auth::auto_flow::CredentialStatus::Ready));
                    if has_missing {
                        let _ =
                            crate::auth::auto_flow::run_interactive_flow(statuses, &token_store)
                                .await;
                    }
                }
            }
        }

        // Re-check: another process may have started Grob while the
        // credential flow was running (interactive prompt, OAuth redirect…).
        if instance::is_instance_running(&config.server.host, effective_port).await {
            eprintln!("✅ Grob already running on port {}", effective_port);
        } else {
            eprintln!("Starting Grob on port {}...", effective_port);
            spawn_background_service(Some(effective_port), cli_config)?;

            if !poll_health(&base_url, HEALTH_POLL_MAX_ATTEMPTS, HEALTH_POLL_INTERVAL_MS).await {
                eprintln!("❌ Grob failed to start within 5 seconds");
                std::process::exit(1);
            }
            we_started = true;
            eprintln!("✅ Grob ready on port {}", effective_port);
        }
    }

    let child_status = {
        let program = &cmd[0];
        let args = &cmd[1..];
        let status = tokio::process::Command::new(program)
            .args(args)
            .env("ANTHROPIC_BASE_URL", &base_url)
            .env("OPENAI_BASE_URL", format!("{}/v1", base_url))
            // Forge CLI uses ANTHROPIC_URL/OPENAI_URL (template appends /messages or /chat/completions)
            .env("ANTHROPIC_URL", format!("{}/v1", base_url))
            .env("OPENAI_URL", format!("{}/v1", base_url))
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

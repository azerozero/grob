use super::common::*;
use crate::providers::AuthType;
use crate::shared::instance;
use crate::{cli, cli::Port};

/// Deprecated or upgradable model hints shown at startup.
const MODEL_HINTS: &[(&str, &str)] = &[
    ("claude-3-5-sonnet-20241022", "Upgrade: claude-sonnet-4-6"),
    (
        "claude-3-5-haiku-20241022",
        "Upgrade: claude-haiku-4-5-20251001",
    ),
    ("gpt-4o", "Upgrade: gpt-5.4"),
    ("gemini-2.0-flash", "Upgrade: gemini-3-flash"),
    ("gemini-1.5-pro", "Upgrade: gemini-3-pro"),
    ("deepseek-v2", "Upgrade: deepseek-v3"),
    ("mistral-medium-latest", "Consider: mistral-large-latest"),
];

/// Starts the Grob service in foreground or detached background mode.
pub async fn cmd_start(
    config: cli::AppConfig,
    config_source: cli::ConfigSource,
    port: Option<u16>,
    detach: bool,
    cli_config: Option<String>,
) -> anyhow::Result<()> {
    print_startup_warnings(&config);

    let effective_port = port.unwrap_or(config.server.port.value());

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

        let log_path = spawn_background_service(port, cli_config)?;
        let base_url = cli::format_base_url(&config.server.host, effective_port);

        // Wait for the listener to actually accept /health before claiming
        // success — otherwise the message lies while the daemon is still
        // binding (or has already crashed).
        if poll_health(&base_url, HEALTH_POLL_MAX_ATTEMPTS, HEALTH_POLL_INTERVAL_MS).await {
            match instance::find_instance_pid(&config.server.host, effective_port).await {
                Some(pid) => println!("✅ Grob started in background (PID: {})", pid),
                None => println!("✅ Grob started in background"),
            }
            println!("📡 Running on port {}", effective_port);
            if let Some(ref path) = log_path {
                println!("📝 Logs: {}", path.display());
            }
            return Ok(());
        }

        let timeout_secs = HEALTH_POLL_MAX_ATTEMPTS as u64 * HEALTH_POLL_INTERVAL_MS / 1000;
        eprintln!("❌ Grob did not become healthy within {}s.", timeout_secs);
        match log_path {
            Some(path) => eprintln!("   Check the daemon log: {}", path.display()),
            None => eprintln!("   No log file available (could not open ~/.grob/grob.log)."),
        }
        anyhow::bail!("background service failed to start");
    }

    // Foreground mode
    let mut config = config;
    if let Some(port) = port {
        config.server.port = Port::new(port).expect("valid port");
    }

    if instance::is_instance_running(&config.server.host, config.server.port.value()).await {
        if let Some(pid) =
            instance::find_instance_pid(&config.server.host, config.server.port.value()).await
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

    // Pre-flight credential check (interactive, only when TTY is available).
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
                        crate::auth::auto_flow::run_interactive_flow(statuses, &token_store).await;
                }
            }
        }
    }

    start_foreground(config, config_source).await?;
    Ok(())
}

/// Prints model upgrade hints and missing credential warnings at startup.
fn print_startup_warnings(config: &cli::AppConfig) {
    // Model hints
    let mut hints = Vec::new();
    for model in &config.models {
        for mapping in &model.mappings {
            for (old, hint) in MODEL_HINTS {
                if mapping.actual_model == *old {
                    hints.push(format!("  {} — {}", old, hint));
                }
            }
        }
    }
    if !hints.is_empty() {
        eprintln!("Model hints:");
        for h in &hints {
            eprintln!("{}", h);
        }
        eprintln!();
    }

    // Missing credentials
    let mut missing = Vec::new();
    for provider in &config.providers {
        if provider.enabled == Some(false) {
            continue;
        }
        if provider.auth_type == AuthType::OAuth {
            continue;
        }
        if let Some(ref key) = provider.api_key {
            if let Some(var) = secrecy::ExposeSecret::expose_secret(key).strip_prefix('$') {
                if std::env::var(var).is_err() {
                    missing.push(format!("  {} needs ${} (not set)", provider.name, var));
                }
            }
        }
    }
    if !missing.is_empty() {
        eprintln!("Missing credentials:");
        for m in &missing {
            eprintln!("{}", m);
        }
        eprintln!();
    }
}

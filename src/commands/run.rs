use crate::{cli, server};

pub async fn cmd_run(
    mut config: cli::AppConfig,
    config_source: cli::ConfigSource,
    port: Option<u16>,
    host: Option<String>,
) -> anyhow::Result<()> {
    if let Some(port) = port {
        config.server.port = port;
    }
    config.server.host = host.unwrap_or_else(|| "::".to_string());

    tracing::info!(
        "🐳 Container mode: {}:{}",
        config.server.host,
        config.server.port
    );

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

    server::start_server(config, config_source, shutdown).await
}

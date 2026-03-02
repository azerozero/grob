//! Server lifecycle: bind, serve, drain, and OAuth callback spawning.

use super::{oauth_handlers, AppState};
use crate::cli::AppConfig;
use axum::{routing::get, Router as AxumRouter};
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info, warn};

pub(super) async fn bind_and_serve(
    config: &AppConfig,
    app: axum::Router,
    shutdown_signal: impl std::future::Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let addr = crate::cli::format_bind_addr(&config.server.host, config.server.port.value());

    #[cfg(feature = "tls")]
    let tls_manual = config.server.tls.enabled
        && !config.server.tls.cert_path.is_empty()
        && !config.server.tls.key_path.is_empty();
    #[cfg(not(feature = "tls"))]
    let tls_manual = false;

    #[cfg(feature = "acme")]
    let tls_acme = config.server.tls.acme.enabled;
    #[cfg(not(feature = "acme"))]
    let tls_acme = false;

    let tls_enabled = tls_manual || tls_acme;

    #[cfg(not(feature = "tls"))]
    if config.server.tls.enabled {
        anyhow::bail!("TLS is enabled in config but grob was built without the `tls` feature. Rebuild with: cargo build --features tls");
    }

    #[cfg(not(feature = "acme"))]
    if config.server.tls.acme.enabled {
        anyhow::bail!("ACME is enabled in config but grob was built without the `acme` feature. Rebuild with: cargo build --features acme");
    }

    if !tls_enabled {
        let listener = crate::net::bind_reuseport(&addr).await?;
        info!("Server listening on {} (SO_REUSEPORT)", addr);
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal)
            .await?;
    } else if tls_acme {
        #[cfg(feature = "acme")]
        {
            let acceptor = crate::acme::build_acme_acceptor(&config.server.tls.acme)?;
            info!("Server listening on {} (ACME TLS, SO_REUSEPORT)", addr);
            let listener = crate::net::bind_reuseport(&addr).await?;
            axum_server::Server::bind(addr.parse()?)
                .acceptor(acceptor)
                .serve(app.into_make_service())
                .await?;
            drop(listener);
        }
    } else {
        #[cfg(feature = "tls")]
        {
            use axum_server::tls_rustls::RustlsConfig;
            let rustls_config = RustlsConfig::from_pem_file(
                &config.server.tls.cert_path,
                &config.server.tls.key_path,
            )
            .await?;
            info!("Server listening on {} (TLS, SO_REUSEPORT)", addr);
            let std_listener = crate::net::bind_reuseport_std(&addr)?;
            axum_server::from_tcp_rustls(std_listener, rustls_config)
                .serve(app.into_make_service())
                .await?;
        }
    }

    Ok(())
}

pub(super) async fn drain_in_flight(state: &Arc<AppState>) {
    let drain_start = std::time::Instant::now();
    let drain_timeout = std::time::Duration::from_secs(30);
    loop {
        let active = state
            .active_requests
            .load(std::sync::atomic::Ordering::Relaxed);
        if active == 0 {
            info!("All in-flight requests drained");
            break;
        }
        if drain_start.elapsed() >= drain_timeout {
            warn!(
                "Drain timeout reached with {} requests still in-flight",
                active
            );
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

/// Spawn the OAuth callback server (required for OpenAI Codex OAuth)
pub(super) fn spawn_oauth_callback(oauth_state: Arc<AppState>) {
    let port = oauth_state.snapshot().config.server.oauth_callback_port;
    tokio::spawn(async move {
        let oauth_callback_app = AxumRouter::new()
            .route("/auth/callback", get(oauth_handlers::oauth_callback))
            .with_state(oauth_state);

        let oauth_addr = format!("127.0.0.1:{}", port);
        match TcpListener::bind(&oauth_addr).await {
            Ok(oauth_listener) => {
                info!("OAuth callback server listening on {}", oauth_addr);
                if let Err(e) = axum::serve(oauth_listener, oauth_callback_app).await {
                    error!("OAuth callback server error: {}", e);
                }
            }
            Err(e) => {
                error!(
                    "Failed to bind OAuth callback server on {}: {}",
                    oauth_addr, e
                );
                error!(
                    "OpenAI Codex OAuth will not work. Port {} must be available.",
                    port
                );
            }
        }
    });
}

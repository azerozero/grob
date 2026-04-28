//! Server lifecycle: bind, serve, drain, and OAuth callback spawning.
//!
//! TLS uses axum-server with rustls. The `rustls-pemfile` transitive dep
//! is tracked under RUSTSEC-2025-0134 until axum-server migrates to
//! `rustls-pki-types`.

use super::{oauth_handlers, AppState};
use crate::models::config::AppConfig;
use axum::{routing::get, Router as AxumRouter};
use std::sync::Arc;
use tracing::{error, info, warn};

/// Binds the server socket and serves with optional TLS and graceful shutdown.
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

    // Label reflects the actual socket option used per platform.
    #[cfg(all(unix, feature = "socket-opts"))]
    const REUSE_LABEL: &str = "SO_REUSEPORT";
    #[cfg(all(not(unix), feature = "socket-opts"))]
    const REUSE_LABEL: &str = "SO_REUSEADDR";
    #[cfg(not(feature = "socket-opts"))]
    const REUSE_LABEL: &str = "plain";

    if !tls_enabled {
        let listener = crate::shared::net::bind_reuseport(&addr).await?;
        info!("Server listening on {} ({})", addr, REUSE_LABEL);
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal)
            .await?;
    } else if tls_acme {
        #[cfg(feature = "acme")]
        {
            let acceptor = crate::shared::acme::build_acme_acceptor(&config.server.tls.acme)?;
            info!("Server listening on {} (ACME TLS, {})", addr, REUSE_LABEL);
            let listener = crate::shared::net::bind_reuseport(&addr).await?;
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
            info!("Server listening on {} (TLS, {})", addr, REUSE_LABEL);
            let std_listener = crate::shared::net::bind_reuseport_std(&addr)?;
            axum_server::from_tcp_rustls(std_listener, rustls_config)
                .serve(app.into_make_service())
                .await?;
        }
    }

    Ok(())
}

/// Waits for all active requests to complete or times out after 30 seconds.
pub(super) async fn drain_in_flight(state: &Arc<AppState>) {
    let drain_start = std::time::Instant::now();
    // NOTE: 30s matches Kubernetes default terminationGracePeriodSeconds and
    // covers the longest typical LLM streaming response (~20s for 4K tokens).
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

/// Spawn the OAuth callback server (required for OpenAI Codex OAuth).
///
/// Tries the configured `oauth_callback_port` first, then falls back to up
/// to [`OAUTH_CALLBACK_BIND_ATTEMPTS`] adjacent ports if the default is busy.
/// The actually-bound port is stored in
/// [`AppState::actual_oauth_callback_port`] so handlers can build `redirect_uri`
/// values that match the live listener.
pub(super) fn spawn_oauth_callback(oauth_state: Arc<AppState>) {
    let configured_port = oauth_state.snapshot().config.server.oauth_callback_port;
    tokio::spawn(async move {
        let oauth_callback_app = AxumRouter::new()
            .route("/auth/callback", get(oauth_handlers::oauth_callback))
            .with_state(oauth_state.clone());

        // NOTE: Bind to 127.0.0.1 because OAuth providers (OpenAI Codex, Gemini)
        // redirect to a literal `localhost`/`127.0.0.1` callback URL.
        match crate::shared::net::bind_with_port_retry(
            "127.0.0.1",
            configured_port,
            OAUTH_CALLBACK_BIND_ATTEMPTS,
        )
        .await
        {
            Ok((oauth_listener, actual_port)) => {
                oauth_state
                    .actual_oauth_callback_port
                    .store(actual_port, std::sync::atomic::Ordering::Relaxed);
                if actual_port == configured_port {
                    info!(
                        "OAuth callback server listening on 127.0.0.1:{}",
                        actual_port
                    );
                } else {
                    warn!(
                        "OAuth callback port {} busy; bound on 127.0.0.1:{} instead",
                        configured_port, actual_port
                    );
                }
                if let Err(e) = axum::serve(oauth_listener, oauth_callback_app).await {
                    error!("OAuth callback server error: {}", e);
                }
            }
            Err(e) => {
                let last_port =
                    configured_port.saturating_add(OAUTH_CALLBACK_BIND_ATTEMPTS.saturating_sub(1));
                error!(
                    "Failed to bind OAuth callback server on 127.0.0.1 in port range {}..={}: {:#}",
                    configured_port, last_port, e
                );
                error!(
                    "OpenAI Codex / Gemini OAuth will not work. Free a port in {}..={} or set server.oauth_callback_port.",
                    configured_port, last_port
                );
            }
        }
    });
}

/// Maximum number of adjacent ports tried when binding the OAuth callback server.
///
/// The configured port is the first attempt; subsequent attempts increment by 1.
pub(super) const OAUTH_CALLBACK_BIND_ATTEMPTS: u16 =
    crate::shared::net::DEFAULT_PORT_RETRY_ATTEMPTS;

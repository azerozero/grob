//! Axum HTTP server, application state, and request handlers.

pub(crate) mod audit;
mod budget;
mod config_api;
pub(crate) mod dispatch;
mod error;
pub mod fan_out;
mod handlers;
pub(crate) mod helpers;
mod init;
mod middleware;
mod oauth_handlers;
pub mod openai_compat;

pub use audit::AuditEntryBuilder;
pub(crate) use audit::{log_audit, AuditCompliance, AuditParams};
pub(crate) use budget::{
    calculate_cost, check_budget, is_provider_subscription, is_retryable, record_request_metrics,
    record_spend, retry_delay, RequestMetrics, MAX_RETRIES,
};
pub use error::AppError;
pub(crate) use helpers::{
    format_route_type, inject_continuation_text, resolve_provider_mappings,
    sanitize_provider_response, should_inject_continuation,
};
pub(crate) use init::{
    init_auth, init_core_services, init_dlp, init_observability, init_security, maybe_preset_sync,
};
pub(crate) use middleware::{
    apply_transparency_headers, auth_middleware, extract_api_credential, extract_client_ip,
    rate_limit_check_middleware, request_id_middleware, security_headers_response_middleware,
    should_apply_transparency, RequestId,
};

use crate::auth::TokenStore;
use crate::cli::AppConfig;
use crate::features::dlp::session::DlpSessionManager;
use crate::features::token_pricing::SharedPricingTable;
use crate::providers::ProviderRegistry;
use crate::router::Router;
use crate::security::provider_scorer::ProviderScorer;
use crate::security::{AuditLog, RateLimiter};
use crate::traits;
use axum::{
    body::Body,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router as AxumRouter,
};
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::limit::RequestBodyLimitLayer;
use tracing::{error, info, warn};

/// Reloadable components - rebuilt on config reload
pub struct ReloadableState {
    pub config: AppConfig,
    pub router: Router,
    pub provider_registry: Arc<ProviderRegistry>,
    /// Pre-computed index: lowercase model name → index into config.models (O(1) lookup)
    pub model_index: std::collections::HashMap<String, usize>,
}

impl ReloadableState {
    pub(crate) fn new(
        config: AppConfig,
        router: Router,
        provider_registry: Arc<ProviderRegistry>,
    ) -> Self {
        let model_index = config
            .models
            .iter()
            .enumerate()
            .map(|(i, m)| (m.name.to_lowercase(), i))
            .collect();
        Self {
            config,
            router,
            provider_registry,
            model_index,
        }
    }

    /// O(1) model config lookup by name (case-insensitive)
    pub fn find_model(&self, name: &str) -> Option<&crate::cli::ModelConfig> {
        self.model_index
            .get(&name.to_lowercase())
            .map(|&idx| &self.config.models[idx])
    }
}

/// Observability-related state (metrics, tracing, spend tracking).
pub struct ObservabilityState {
    pub message_tracer: Arc<dyn traits::Tracer>,
    pub metrics_handle: metrics_exporter_prometheus::PrometheusHandle,
    pub spend_tracker: tokio::sync::Mutex<Box<dyn traits::SpendTracking>>,
    pub pricing_table: SharedPricingTable,
}

/// Security-related state (auth, rate limiting, DLP, circuit breakers, audit, cache, tap).
pub struct SecurityState {
    pub jwt_validator: Option<Arc<crate::auth::JwtValidator>>,
    pub rate_limiter: Option<Arc<RateLimiter>>,
    pub dlp_sessions: Option<Arc<DlpSessionManager>>,
    pub circuit_breakers: Option<Arc<dyn traits::ProviderAvailability>>,
    pub audit_log: Option<Arc<AuditLog>>,
    pub response_cache: Option<Arc<crate::cache::ResponseCache>>,
    pub tap_sender: Option<Arc<crate::features::tap::TapSender>>,
    pub provider_scorer: Option<Arc<ProviderScorer>>,
}

/// Application state shared across handlers
pub struct AppState {
    /// Reloadable state behind a single lock for atomic updates
    pub(crate) inner: std::sync::RwLock<Arc<ReloadableState>>,

    /// Persistent state - NOT reloaded
    pub token_store: TokenStore,
    pub config_source: crate::cli::ConfigSource,
    pub active_requests: std::sync::atomic::AtomicU64,
    /// Server start time (for health/upgrade coordination)
    pub started_at: chrono::DateTime<chrono::Utc>,

    /// Metrics, tracing, spend tracking
    pub observability: ObservabilityState,
    /// Auth, rate limiting, DLP, circuit breakers, audit, cache, tap
    pub security: SecurityState,
}

impl AppState {
    /// Get a snapshot of current reloadable state.
    ///
    /// The `unwrap_or_else(|e| e.into_inner())` is safe here: a poisoned RwLock
    /// means a writer panicked during `reload_config`. The inner `Arc<ReloadableState>`
    /// is still valid (it's an atomic ref-count swap, not an in-place mutation),
    /// so readers can continue with the last successfully committed snapshot.
    pub fn snapshot(&self) -> Arc<ReloadableState> {
        self.inner.read().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

/// Start the HTTP server with graceful shutdown support.
/// When the `shutdown_signal` future completes, the server stops accepting new
/// connections and drains in-flight requests (up to 30 s).
pub async fn start_server(
    config: AppConfig,
    config_source: crate::cli::ConfigSource,
    shutdown_signal: impl std::future::Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let (grob_store, token_store, provider_registry) = init_core_services(&config).await?;
    let (message_tracer, spend_tracker, pricing_table, metrics_handle) =
        init_observability(&config, &grob_store).await?;
    let dlp_sessions = init_dlp(&config);
    let jwt_validator = init_auth(&config).await?;

    #[cfg(feature = "tap")]
    let tap_sender = crate::features::tap::init_tap(&config.tap);
    #[cfg(not(feature = "tap"))]
    let tap_sender: Option<Arc<crate::features::tap::TapSender>> = None;

    let router = Router::new(config.clone());
    let reloadable = Arc::new(ReloadableState::new(
        config.clone(),
        router,
        provider_registry,
    ));

    let (rate_limiter, circuit_breakers, audit_log, response_cache) = init_security(&config)?;

    let provider_scorer = if config.security.adaptive_scoring {
        let scorer_config = crate::security::provider_scorer::ScorerConfig {
            latency_alpha: config.security.scoring_latency_alpha,
            window_size: config.security.scoring_window_size,
            decay_rate: config.security.scoring_decay_rate,
        };
        let scorer = Arc::new(ProviderScorer::new(scorer_config, circuit_breakers.clone()));
        info!(
            "📊 Adaptive provider scoring enabled (window={}, alpha={}, decay={})",
            config.security.scoring_window_size,
            config.security.scoring_latency_alpha,
            config.security.scoring_decay_rate
        );
        Some(scorer)
    } else {
        None
    };

    // Coerce concrete types to trait objects for testability
    let tracer: Arc<dyn traits::Tracer> = message_tracer;
    let tracker: Box<dyn traits::SpendTracking> = Box::new(spend_tracker);
    let availability: Option<Arc<dyn traits::ProviderAvailability>> =
        circuit_breakers.map(|cb| cb as Arc<dyn traits::ProviderAvailability>);

    let state = Arc::new(AppState {
        inner: std::sync::RwLock::new(reloadable),
        token_store,
        config_source,
        active_requests: std::sync::atomic::AtomicU64::new(0),
        started_at: chrono::Utc::now(),
        observability: ObservabilityState {
            message_tracer: tracer,
            metrics_handle,
            spend_tracker: tokio::sync::Mutex::new(tracker),
            pricing_table,
        },
        security: SecurityState {
            jwt_validator,
            rate_limiter,
            dlp_sessions,
            circuit_breakers: availability,
            audit_log,
            response_cache,
            tap_sender,
            provider_scorer,
        },
    });

    maybe_preset_sync(&config).await;

    let app = build_app_router(&config, state.clone());
    let oauth_state = state.clone();
    let drain_state = state.clone();

    spawn_oauth_callback(oauth_state);
    bind_and_serve(&config, app, shutdown_signal).await?;
    drain_in_flight(&drain_state).await;

    Ok(())
}

fn build_app_router(config: &AppConfig, state: Arc<AppState>) -> axum::Router {
    let app = AxumRouter::new()
        .route("/v1/messages", post(handlers::handle_messages))
        .route(
            "/v1/messages/count_tokens",
            post(handlers::handle_count_tokens),
        )
        .route(
            "/v1/chat/completions",
            post(handlers::handle_openai_chat_completions),
        )
        .route("/v1/models", get(handlers::handle_openai_models))
        .route("/health", get(health_check))
        .route("/live", get(liveness_check))
        .route("/ready", get(readiness_check))
        .route("/metrics", get(metrics_endpoint))
        .route("/api/config", get(config_api::get_config_json))
        .route("/api/config", post(config_api::update_config_json))
        .route("/api/config/reload", post(config_api::reload_config))
        .route("/api/scores", get(scores_endpoint))
        .route(
            "/api/oauth/authorize",
            post(oauth_handlers::oauth_authorize),
        )
        .route("/api/oauth/exchange", post(oauth_handlers::oauth_exchange))
        .route("/api/oauth/callback", get(oauth_handlers::oauth_callback))
        .route("/auth/callback", get(oauth_handlers::oauth_callback))
        .route("/api/oauth/tokens", get(oauth_handlers::oauth_list_tokens))
        .route(
            "/api/oauth/tokens/delete",
            post(oauth_handlers::oauth_delete_token),
        )
        .route(
            "/api/oauth/tokens/refresh",
            post(oauth_handlers::oauth_refresh_token),
        );

    let app = app.layer(axum::middleware::from_fn_with_state(
        state.clone(),
        auth_middleware,
    ));

    let app = app.layer(axum::middleware::from_fn_with_state(
        state.clone(),
        rate_limit_check_middleware,
    ));

    let app = if config.security.security_headers {
        app.layer(axum::middleware::from_fn(
            security_headers_response_middleware,
        ))
    } else {
        app
    };

    let app = app.layer(RequestBodyLimitLayer::new(
        config.security.max_body_size.value(),
    ));
    let app = app.layer(axum::middleware::from_fn(request_id_middleware));

    app.with_state(state)
}

async fn bind_and_serve(
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
        info!("🚀 Server listening on {} (SO_REUSEPORT)", addr);
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal)
            .await?;
    } else if tls_acme {
        #[cfg(feature = "acme")]
        {
            let acceptor = crate::acme::build_acme_acceptor(&config.server.tls.acme)?;
            info!("🔒 Server listening on {} (ACME TLS, SO_REUSEPORT)", addr);
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
            info!("🔒 Server listening on {} (TLS, SO_REUSEPORT)", addr);
            let std_listener = crate::net::bind_reuseport_std(&addr)?;
            axum_server::from_tcp_rustls(std_listener, rustls_config)
                .serve(app.into_make_service())
                .await?;
        }
    }

    Ok(())
}

async fn drain_in_flight(state: &Arc<AppState>) {
    let drain_start = std::time::Instant::now();
    let drain_timeout = std::time::Duration::from_secs(30);
    loop {
        let active = state
            .active_requests
            .load(std::sync::atomic::Ordering::Relaxed);
        if active == 0 {
            info!("✅ All in-flight requests drained");
            break;
        }
        if drain_start.elapsed() >= drain_timeout {
            warn!(
                "⚠️ Drain timeout reached with {} requests still in-flight",
                active
            );
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

/// Spawn the OAuth callback server (required for OpenAI Codex OAuth)
fn spawn_oauth_callback(oauth_state: Arc<AppState>) {
    let port = oauth_state.snapshot().config.server.oauth_callback_port;
    tokio::spawn(async move {
        let oauth_callback_app = AxumRouter::new()
            .route("/auth/callback", get(oauth_handlers::oauth_callback))
            .with_state(oauth_state);

        let oauth_addr = format!("127.0.0.1:{}", port);
        match TcpListener::bind(&oauth_addr).await {
            Ok(oauth_listener) => {
                info!("🔐 OAuth callback server listening on {}", oauth_addr);
                if let Err(e) = axum::serve(oauth_listener, oauth_callback_app).await {
                    error!("OAuth callback server error: {}", e);
                }
            }
            Err(e) => {
                error!(
                    "⚠️  Failed to bind OAuth callback server on {}: {}",
                    oauth_addr, e
                );
                error!(
                    "⚠️  OpenAI Codex OAuth will not work. Port {} must be available.",
                    port
                );
            }
        }
    });
}

/// Adaptive provider scores endpoint.
async fn scores_endpoint(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    if let Some(ref scorer) = state.security.provider_scorer {
        let scores = scorer.all_scores().await;
        Json(serde_json::json!({
            "adaptive_scoring": true,
            "scores": scores
        }))
    } else {
        Json(serde_json::json!({
            "adaptive_scoring": false,
            "scores": {}
        }))
    }
}

/// Health check endpoint
async fn health_check(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let active = state
        .active_requests
        .load(std::sync::atomic::Ordering::Relaxed);
    let spend_total = {
        let tracker = state.observability.spend_tracker.lock().await;
        tracker.total()
    };
    let inner = state.snapshot();
    let budget_limit = inner.config.budget.monthly_limit_usd.value();
    Json(serde_json::json!({
        "status": "ok",
        "service": "grob",
        "pid": std::process::id(),
        "started_at": state.started_at.to_rfc3339(),
        "active_requests": active,
        "spend": {
            "total_usd": spend_total,
            "budget_usd": budget_limit,
        }
    }))
}

/// Liveness probe: process is alive, returns 200 always.
async fn liveness_check() -> impl IntoResponse {
    Json(serde_json::json!({"status": "alive"}))
}

/// Readiness probe: check that providers are configured and circuit breakers aren't all open.
async fn readiness_check(State(state): State<Arc<AppState>>) -> Response {
    let inner = state.snapshot();
    let provider_count = inner.provider_registry.list_providers().len();

    if provider_count == 0 {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "status": "not_ready",
                "reason": "no providers configured"
            })),
        )
            .into_response();
    }

    // Check if all circuit breakers are open (all providers degraded)
    if let Some(ref cb) = state.security.circuit_breakers {
        let states = cb.all_states().await;
        if !states.is_empty() {
            let all_open = states
                .values()
                .all(|s| *s == crate::security::CircuitState::Open);
            if all_open {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(serde_json::json!({
                        "status": "not_ready",
                        "reason": "all circuit breakers open"
                    })),
                )
                    .into_response();
            }
        }
    }

    Json(serde_json::json!({
        "status": "ready",
        "providers": provider_count
    }))
    .into_response()
}

/// Prometheus metrics endpoint
async fn metrics_endpoint(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let active = state
        .active_requests
        .load(std::sync::atomic::Ordering::Relaxed);
    metrics::gauge!("grob_active_requests").set(active as f64);

    // Publish spend/budget gauges (point-in-time snapshots → gauges are correct)
    let inner = state.snapshot();
    let tracker = state.observability.spend_tracker.lock().await;
    metrics::gauge!("grob_spend_usd").set(tracker.total());
    let budget_limit = inner.config.budget.monthly_limit_usd.value();
    if budget_limit > 0.0 {
        metrics::gauge!("grob_budget_limit_usd").set(budget_limit);
        metrics::gauge!("grob_budget_remaining_usd").set((budget_limit - tracker.total()).max(0.0));
    }
    drop(tracker);

    // Publish adaptive scoring gauges
    if let Some(ref scorer) = state.security.provider_scorer {
        let details = scorer.all_score_details().await;
        for (provider, (success_rate, latency_ewma, score)) in &details {
            metrics::gauge!(
                "grob_provider_score",
                "provider" => provider.clone()
            )
            .set(*score);
            metrics::gauge!(
                "grob_provider_latency_ewma_ms",
                "provider" => provider.clone()
            )
            .set(*latency_ewma);
            metrics::gauge!(
                "grob_provider_success_rate",
                "provider" => provider.clone()
            )
            .set(*success_rate);
        }
    }

    let body = state.observability.metrics_handle.render();
    // Header and body are controlled string constants; builder cannot fail.
    Response::builder()
        .header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        .body(Body::from(body))
        .unwrap()
}

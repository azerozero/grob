//! Axum HTTP server, application state, and request handlers.

/// Audit logging subsystem for compliance and observability.
pub(crate) mod audit;
mod budget;
mod config_api;
/// Core dispatch pipeline: DLP, cache, route, provider loop.
pub(crate) mod dispatch;
mod endpoints;
mod error;
/// Parallel multi-provider dispatch (fan-out strategy).
pub mod fan_out;
mod handlers;
/// Shared helper utilities for routing, sanitization, and injection.
pub(crate) mod helpers;
mod init;
mod lifecycle;
mod middleware;
mod oauth_handlers;
/// OpenAI `/v1/chat/completions` compatibility translation layer.
pub mod openai_compat;
/// OpenAI Responses API (`/v1/responses`) compatibility translation layer.
pub mod responses_compat;
mod watch_sse;

pub use audit::AuditEntryBuilder;
pub(crate) use audit::{log_audit, AuditCompliance, AuditParams};
pub(crate) use budget::{
    calculate_cost, check_budget, is_provider_subscription, is_retryable, record_request_metrics,
    record_spend, retry_delay, RequestMetrics, MAX_RETRIES,
};
pub use error::AppError;
pub(crate) use helpers::{
    format_route_type, inject_continuation_text, resolve_provider_mappings,
    sanitize_provider_response_reported, should_inject_continuation,
};
#[cfg(feature = "mcp")]
pub(crate) use init::init_mcp;
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
    routing::{get, post},
    Router as AxumRouter,
};
use std::sync::Arc;
use tower_http::limit::RequestBodyLimitLayer;
use tracing::info;

/// Reloadable components - rebuilt on config reload
pub struct ReloadableState {
    /// Active application configuration snapshot.
    pub config: AppConfig,
    /// Request routing engine for task-type classification.
    pub router: Router,
    /// Registry of all configured LLM providers.
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
    /// Distributed tracing implementation for request spans.
    pub message_tracer: Arc<dyn traits::Tracer>,
    /// Prometheus metrics exporter handle for `/metrics` endpoint.
    pub metrics_handle: metrics_exporter_prometheus::PrometheusHandle,
    /// Persistent monthly spend tracker with budget enforcement.
    pub spend_tracker: tokio::sync::Mutex<Box<dyn traits::SpendTracking>>,
    /// Shared token pricing table for cost calculation.
    pub pricing_table: SharedPricingTable,
}

/// Security-related state (auth, rate limiting, DLP, circuit breakers, audit, cache, tap, MCP).
pub struct SecurityState {
    /// JWT token validator for OAuth-authenticated requests.
    pub jwt_validator: Option<Arc<crate::auth::JwtValidator>>,
    /// Per-client rate limiter for request throttling.
    pub rate_limiter: Option<Arc<RateLimiter>>,
    /// DLP session manager for secret scanning and PII redaction.
    pub dlp_sessions: Option<Arc<DlpSessionManager>>,
    /// Circuit breakers tracking provider availability.
    pub circuit_breakers: Option<Arc<dyn traits::ProviderAvailability>>,
    /// Append-only audit log for compliance recording.
    pub audit_log: Option<Arc<AuditLog>>,
    /// LRU response cache for deterministic requests.
    pub response_cache: Option<Arc<crate::cache::ResponseCache>>,
    /// Webhook tap sender for event emission.
    pub tap_sender: Option<Arc<crate::features::tap::TapSender>>,
    /// Adaptive provider scorer for latency-aware routing.
    pub provider_scorer: Option<Arc<ProviderScorer>>,
    /// MCP tool matrix and JSON-RPC server state.
    #[cfg(feature = "mcp")]
    pub mcp: Option<Arc<crate::features::mcp::McpState>>,
}

/// Application state shared across handlers
pub struct AppState {
    /// Reloadable state behind a single lock for atomic updates
    pub(crate) inner: std::sync::RwLock<Arc<ReloadableState>>,

    /// Persistent state - NOT reloaded
    pub token_store: TokenStore,
    /// Shared storage backend (redb) for virtual key lookups and spend tracking.
    pub grob_store: Arc<crate::storage::GrobStore>,
    /// Identifies how the configuration was loaded (file, env, CLI).
    pub config_source: crate::cli::ConfigSource,
    /// Counter of currently in-flight requests for graceful drain.
    pub active_requests: std::sync::atomic::AtomicU64,
    /// Server start time (for health/upgrade coordination)
    pub started_at: chrono::DateTime<chrono::Utc>,

    /// Metrics, tracing, spend tracking
    pub observability: ObservabilityState,
    /// Auth, rate limiting, DLP, circuit breakers, audit, cache, tap
    pub security: SecurityState,
    /// Live event bus for `grob watch` TUI and SSE endpoint.
    pub event_bus: crate::features::watch::EventBus,
    /// External log exporter for structured request/response logs.
    pub log_exporter: Option<Arc<crate::features::log_export::LogExporter>>,
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

    #[cfg(feature = "mcp")]
    let mcp_state = init_mcp(&config, &provider_registry);

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

    let log_exporter = crate::features::log_export::init_log_exporter(&config.log_export);

    let event_bus = crate::features::watch::EventBus::new();

    let state = Arc::new(AppState {
        inner: std::sync::RwLock::new(reloadable),
        token_store,
        grob_store,
        config_source,
        active_requests: std::sync::atomic::AtomicU64::new(0),
        started_at: chrono::Utc::now(),
        event_bus,
        log_exporter,
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
            #[cfg(feature = "mcp")]
            mcp: mcp_state,
        },
    });

    maybe_preset_sync(&config).await;

    let app = build_app_router(&config, state.clone());
    let oauth_state = state.clone();
    let drain_state = state.clone();

    // Validate all model mappings in background (non-blocking).
    // Warns about dead fallback models without delaying startup.
    {
        let validation_state = state.clone();
        tokio::spawn(async move {
            let inner = validation_state.snapshot();
            info!("Validating model mappings...");
            let results =
                crate::preset::validate_config(&inner.config, &inner.provider_registry).await;
            crate::preset::log_validation_results(&results);
        });
    }

    lifecycle::spawn_oauth_callback(oauth_state);
    lifecycle::bind_and_serve(&config, app, shutdown_signal).await?;
    lifecycle::drain_in_flight(&drain_state).await;
    crate::otel::shutdown_otel();

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
        .route("/v1/responses", post(handlers::handle_responses))
        .route("/v1/models", get(handlers::handle_openai_models))
        .route("/health", get(endpoints::health_check))
        .route("/live", get(endpoints::liveness_check))
        .route("/ready", get(endpoints::readiness_check))
        .route("/metrics", get(endpoints::metrics_endpoint))
        .route("/api/config", get(config_api::get_config_json))
        .route("/api/config", post(config_api::update_config_json))
        .route("/api/config/reload", post(config_api::reload_config))
        .route("/api/scores", get(endpoints::scores_endpoint))
        .route("/api/events", get(watch_sse::watch_events_sse))
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

    // MCP routes (conditionally compiled and enabled)
    #[cfg(feature = "mcp")]
    let app = if state.security.mcp.is_some() {
        app.route("/mcp", post(crate::features::mcp::server::handle_mcp_rpc))
            .route(
                "/api/tool-matrix",
                get(crate::features::mcp::server::handle_matrix_report),
            )
    } else {
        app
    };

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

    // Tape recorder layer: outermost to capture raw HTTP before any transformation.
    #[cfg(feature = "harness")]
    let app = {
        if let Ok(tape_path) = std::env::var("GROB_HARNESS_RECORD") {
            match futures::executor::block_on(crate::features::harness::TapeWriter::new(
                std::path::Path::new(&tape_path),
            )) {
                Ok(writer) => {
                    info!(path = %tape_path, "Tape recorder enabled");
                    app.layer(crate::features::harness::TapeRecorderLayer::new(writer))
                }
                Err(e) => {
                    tracing::error!(error = %e, "Failed to open tape file, recording disabled");
                    app
                }
            }
        } else {
            app
        }
    };

    app.with_state(state)
}

// ── Compile-time Send + Sync assertions ──
// Axum requires handler state to be Send + Sync + 'static.
// These assertions catch accidental regressions at compile time.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<AppState>();
    assert_send_sync::<ReloadableState>();
};

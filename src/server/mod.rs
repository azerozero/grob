//! Axum HTTP server, application state, and request handlers.

/// Audit logging subsystem for compliance and observability.
pub(crate) mod audit;
mod budget;
mod config_api;
/// Centralized deny-list for configuration updates.
pub(crate) mod config_guard;
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
/// MCP JSON-RPC handlers (Axum glue + self-tuning configuration).
#[cfg(feature = "mcp")]
pub(crate) mod mcp_handlers;
mod middleware;
mod oauth_handlers;
/// OpenAI `/v1/chat/completions` compatibility translation layer.
pub mod openai_compat;
/// OpenAI Responses API (`/v1/responses`) compatibility translation layer.
pub mod responses_compat;
/// Unified JSON-RPC 2.0 Control Plane.
pub mod rpc;
#[cfg(feature = "watch")]
mod watch_sse;

pub use audit::AuditEntryBuilder;
pub(crate) use audit::{log_audit, AuditCompliance, AuditParams};
pub(crate) use budget::{
    calculate_cost, check_budget_for_tenant, effective_token_counts, estimate_input_tokens,
    estimate_output_tokens, is_auth_revoked_error, is_estimate_mode, is_provider_subscription,
    is_retryable, provider_max_retries, record_request_metrics, record_spend, retry_delay,
    tokens_from_chars, RequestMetrics,
};
pub use error::{ErrorVariantTag, RequestError};
pub(crate) use helpers::{
    format_route_type, inject_continuation_text, resolve_provider_mappings,
    sanitize_provider_response_reported, should_inject_continuation,
};
#[cfg(feature = "mcp")]
pub(crate) use init::init_mcp;
pub(crate) use init::{
    emit_tee_attestation, init_auth, init_core_services, init_dlp, init_observability,
    init_provider_scorer, init_security, init_tool_spike_detector, maybe_preset_sync,
    spawn_background_tasks,
};
pub(crate) use middleware::{
    apply_transparency_headers, audit_log_layer, auth_middleware, extract_api_credential,
    extract_client_ip, rate_limit_check_middleware, request_id_middleware,
    security_headers_response_middleware, should_apply_transparency, tenant_required_middleware,
};
pub use middleware::{
    capture_audit_input, emit_request_processed, AuditMiddlewareCapture, AuditedAlready, RequestId,
};

use crate::auth::TokenStore;
use crate::config::AppConfig;
use crate::features::dlp::session::DlpSessionManager;
use crate::features::token_pricing::SharedPricingTable;
use crate::providers::ProviderRegistry;
use crate::routing::classify::Router;
use crate::security::{AuditLog, RateLimiter};
use crate::traits;
use axum::{
    routing::{get, post},
    Router as AxumRouter,
};
use std::sync::Arc;
use tower_http::limit::RequestBodyLimitLayer;
use tracing::{info, warn};

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
    /// Policy matcher for per-tenant/zone/compliance request evaluation.
    ///
    /// Rebuilt on every `/api/config/reload` because `[[policies]]` changes are
    /// part of the reloadable config — policy rule updates take effect immediately.
    #[cfg(feature = "policies")]
    pub policy_matcher: Option<Arc<crate::features::policies::matcher::PolicyMatcher>>,
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
        #[cfg(feature = "policies")]
        let policy_matcher = init::init_policies(&config);
        Self {
            config,
            router,
            provider_registry,
            model_index,
            #[cfg(feature = "policies")]
            policy_matcher,
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
    /// Optional bearer token gating `/metrics`. `None` = endpoint is public
    /// (the default). Resolved once at startup from `[metrics]` config.
    pub metrics_bearer_token: Option<secrecy::SecretString>,
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
    pub provider_scorer: Option<Arc<crate::security::provider_scorer::ProviderScorer>>,
    /// MCP tool matrix and JSON-RPC server state.
    #[cfg(feature = "mcp")]
    pub mcp: Option<Arc<crate::features::mcp::McpState>>,
    /// Universal tool layer for injection, aliasing, and capability gating.
    pub tool_layer: Option<Arc<crate::features::tool_layer::ToolLayer>>,
    /// Per-session tool-call spike anomaly detector (T-AD1).
    pub tool_spike_detector: Option<Arc<crate::security::ToolSpikeDetector>>,
}

/// Application state shared across handlers
pub struct AppState {
    /// Reloadable state behind a single lock for atomic updates
    pub(crate) inner: std::sync::RwLock<Arc<ReloadableState>>,

    /// Persistent state - NOT reloaded
    pub token_store: TokenStore,
    /// Shared storage backend for virtual key lookups and spend tracking.
    pub grob_store: Arc<crate::storage::GrobStore>,
    /// Identifies how the configuration was loaded (file, env, CLI).
    pub config_source: crate::cli::ConfigSource,
    /// Counter of currently in-flight requests for graceful drain.
    pub active_requests: std::sync::atomic::AtomicU64,
    /// Server start time (for health/upgrade coordination)
    pub started_at: chrono::DateTime<chrono::Utc>,
    /// TCP port the OAuth callback server actually bound to.
    ///
    /// The configured `server.oauth_callback_port` is the preferred port; the
    /// callback listener falls back to an adjacent port when it is busy. Handlers
    /// building loopback `redirect_uri` values read this to stay aligned with the
    /// live listener. A value of `0` means the callback server has not bound yet
    /// (or failed to bind).
    pub actual_oauth_callback_port: std::sync::atomic::AtomicU16,

    /// Metrics, tracing, spend tracking
    pub observability: ObservabilityState,
    /// Auth, rate limiting, DLP, circuit breakers, audit, cache, tap
    pub security: SecurityState,
    /// Live event bus for `grob watch` TUI and SSE endpoint.
    pub event_bus: crate::features::watch::EventBus,
    /// External log exporter for structured request/response logs.
    pub log_exporter: Option<Arc<crate::features::log_export::LogExporter>>,
    /// One-shot complexity hint set by the `grob_hint` MCP tool.
    ///
    /// Consumed by the next dispatch that does not carry a header/body hint.
    /// Header/body hints take precedence for their request without consuming
    /// this slot, preserving the MCP one-shot for the next unhinted dispatch.
    #[cfg(feature = "mcp")]
    pub grob_hint: std::sync::Mutex<Option<crate::features::mcp::server::types::ComplexityHint>>,
    /// Pending HIT approval channels keyed by `"{request_id}:{tool_name}"`.
    #[cfg(feature = "policies")]
    pub hit_pending: Arc<crate::features::policies::stream::HitPendingApprovals>,
    /// Dedicated limiter for per-policy `rate_limit` overrides. Separate from
    /// [`SecurityState::rate_limiter`] so policy buckets (custom rps) never
    /// collide with the pre-handler middleware's default-rate buckets.
    #[cfg(feature = "policies")]
    pub policy_rate_limiter: Arc<RateLimiter>,
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

/// Builds a minimal real [`AppState`] for tests.
///
/// Uses `build_recorder().handle()` so no global Prometheus recorder is installed
/// (no process-global singleton contention), an empty in-memory provider registry
/// unless one is supplied, and a throwaway `GrobStore` in a leaked temp dir. Lets
/// unit tests exercise real handlers (`dispatch`, `handle_count_tokens`, RPC key
/// ops) without spinning up the HTTP server.
#[cfg(test)]
pub(crate) fn test_app_state(
    config: AppConfig,
    registry: crate::providers::ProviderRegistry,
) -> Arc<AppState> {
    test_app_state_with_source(
        config,
        registry,
        crate::cli::ConfigSource::File(std::path::PathBuf::from("test.toml")),
    )
}

/// Like [`test_app_state`] but with an explicit [`crate::cli::ConfigSource`].
///
/// Lets reload-path tests point the state at a real on-disk config file so the
/// HTTP/RPC `reload_config` handlers can re-read it.
#[cfg(test)]
pub(crate) fn test_app_state_with_source(
    config: AppConfig,
    registry: crate::providers::ProviderRegistry,
    config_source: crate::cli::ConfigSource,
) -> Arc<AppState> {
    let router = Router::new(config.clone());
    let reloadable = Arc::new(ReloadableState::new(
        config.clone(),
        router,
        Arc::new(registry),
    ));

    let home = tempfile::tempdir().expect("tempdir");
    let grob_store = Arc::new(
        crate::storage::GrobStore::open(&home.path().join("grob.db")).expect("grob store"),
    );
    let token_store = crate::auth::TokenStore::with_store(grob_store.clone()).expect("token store");
    // Keep the storage dir alive for the process; tests are short-lived.
    std::mem::forget(home);

    let message_tracer: Arc<dyn traits::Tracer> = Arc::new(
        crate::shared::message_tracing::MessageTracer::new(config.server.tracing.clone()),
    );
    let spend_tracker: Box<dyn traits::SpendTracking> = Box::new(
        crate::features::token_pricing::spend::SpendTracker::with_store(grob_store.clone()),
    );
    let pricing_table = crate::features::token_pricing::init_pricing_table(&config.pricing);
    let metrics_handle = metrics_exporter_prometheus::PrometheusBuilder::new()
        .build_recorder()
        .handle();

    Arc::new(AppState {
        inner: std::sync::RwLock::new(reloadable),
        token_store,
        grob_store,
        config_source,
        active_requests: std::sync::atomic::AtomicU64::new(0),
        started_at: chrono::Utc::now(),
        actual_oauth_callback_port: std::sync::atomic::AtomicU16::new(0),
        event_bus: crate::features::watch::EventBus::new(),
        log_exporter: None,
        #[cfg(feature = "mcp")]
        grob_hint: std::sync::Mutex::new(None),
        #[cfg(feature = "policies")]
        hit_pending: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        #[cfg(feature = "policies")]
        policy_rate_limiter: Arc::new(crate::security::RateLimiter::new(
            crate::security::RateLimitConfig {
                requests_per_second: 1,
                burst: 1,
            },
        )),
        observability: ObservabilityState {
            message_tracer,
            metrics_handle,
            // Mirror real startup: resolve the optional `/metrics` bearer token
            // from config so tests can exercise both the public and gated paths.
            metrics_bearer_token: config.metrics.resolve_bearer_token().ok().flatten(),
            spend_tracker: tokio::sync::Mutex::new(spend_tracker),
            pricing_table,
        },
        security: SecurityState {
            jwt_validator: None,
            rate_limiter: None,
            dlp_sessions: None,
            circuit_breakers: None,
            audit_log: None,
            response_cache: None,
            tap_sender: None,
            provider_scorer: None,
            #[cfg(feature = "mcp")]
            mcp: None,
            tool_layer: None,
            tool_spike_detector: None,
        },
    })
}

/// Start the HTTP server with graceful shutdown support.
/// When the `shutdown_signal` future completes, the server stops accepting new
/// connections and drains in-flight requests (up to 30 s).
pub async fn start_server(
    config: AppConfig,
    config_source: crate::cli::ConfigSource,
    shutdown_signal: impl std::future::Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    // ── Pre-flight security enforcement ──
    // TEE and FIPS checks run before any service initialization so the
    // process refuses to start (or warns) before opening ports or loading secrets.
    let tee_status = crate::security::tee::enforce_tee(config.tee.mode, &config.tee)?;
    let _fips_status = crate::security::fips::enforce_fips(config.fips.mode)?;

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

    let tool_layer = if config.tool_layer.enabled {
        info!(
            "🔧 Tool layer enabled ({} inject rules, {} aliases)",
            config.tool_layer.inject.len(),
            config.tool_layer.aliases.len(),
        );
        Some(Arc::new(crate::features::tool_layer::ToolLayer::new(
            config.tool_layer.clone(),
        )))
    } else {
        None
    };

    let router = Router::new(config.clone());
    let reloadable = Arc::new(ReloadableState::new(
        config.clone(),
        router,
        provider_registry,
    ));

    let (rate_limiter, circuit_breakers, audit_log, response_cache) = init_security(&config)?;

    emit_tee_attestation(&tee_status, &audit_log);

    let provider_scorer = init_provider_scorer(&config, &circuit_breakers);
    let tool_spike_detector = init_tool_spike_detector(&config);

    // Coerce concrete types to trait objects for testability
    let tracer: Arc<dyn traits::Tracer> = message_tracer;
    let tracker: Box<dyn traits::SpendTracking> = Box::new(spend_tracker);
    let availability: Option<Arc<dyn traits::ProviderAvailability>> =
        circuit_breakers.map(|cb| cb as Arc<dyn traits::ProviderAvailability>);

    let log_exporter = crate::features::log_export::init_log_exporter(&config.log_export);

    // Resolve the optional `/metrics` bearer token once at startup (the file,
    // if set, wins and is trimmed). A configured-but-blank source is a likely
    // misconfiguration, so warn instead of silently leaving `/metrics` public.
    let metrics_bearer_token = config.metrics.resolve_bearer_token().map_err(|e| {
        anyhow::anyhow!(
            "Failed to read [metrics] bearer_token_file '{}': {}",
            config.metrics.bearer_token_file.as_deref().unwrap_or(""),
            e
        )
    })?;
    match (
        &metrics_bearer_token,
        config.metrics.token_source_configured(),
    ) {
        (Some(_), _) => info!("🔒 /metrics requires Authorization: Bearer <token>"),
        (None, true) => {
            warn!(
                "⚠️  [metrics] token source configured but resolved empty — /metrics stays PUBLIC"
            )
        }
        (None, false) => {}
    }

    let event_bus = crate::features::watch::EventBus::new();

    let state = Arc::new(AppState {
        inner: std::sync::RwLock::new(reloadable),
        token_store,
        grob_store,
        config_source,
        active_requests: std::sync::atomic::AtomicU64::new(0),
        started_at: chrono::Utc::now(),
        actual_oauth_callback_port: std::sync::atomic::AtomicU16::new(0),
        event_bus,
        log_exporter,
        #[cfg(feature = "mcp")]
        grob_hint: std::sync::Mutex::new(None),
        #[cfg(feature = "policies")]
        hit_pending: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        #[cfg(feature = "policies")]
        policy_rate_limiter: Arc::new(RateLimiter::new(crate::security::RateLimitConfig {
            requests_per_second: 1,
            burst: 1,
        })),
        observability: ObservabilityState {
            message_tracer: tracer,
            metrics_handle,
            metrics_bearer_token,
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
            tool_layer,
            tool_spike_detector,
        },
    });

    maybe_preset_sync(&config);
    spawn_background_tasks(&state);

    let app = build_app_router(&config, state.clone());
    lifecycle::spawn_oauth_callback(state.clone());
    lifecycle::bind_and_serve(&config, app, shutdown_signal).await?;
    lifecycle::drain_in_flight(&state).await;
    crate::shared::otel::shutdown_otel();

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

    // ── JSON-RPC 2.0 Control Plane ──
    let rpc_state = state.clone();
    let app = app.route(
        "/rpc",
        post(
            move |headers: axum::http::HeaderMap, body: axum::body::Bytes| {
                handle_rpc(rpc_state, headers, body)
            },
        ),
    );

    // Live event stream — only available when the watch feature is compiled in.
    #[cfg(feature = "watch")]
    let app = app.route("/api/events", get(watch_sse::watch_events_sse));

    // HIT approval endpoint — allows TUI, webhooks, and external systems to approve/deny.
    #[cfg(feature = "policies")]
    let app = app.route("/api/hit/approve", post(hit_approve_handler));

    // MCP routes (conditionally compiled and enabled)
    #[cfg(feature = "mcp")]
    let app = if state.security.mcp.is_some() {
        app.route("/mcp", post(mcp_handlers::handle_mcp_rpc))
            .route("/api/tool-matrix", get(mcp_handlers::handle_matrix_report))
    } else {
        app
    };

    // tenant_required runs *after* auth so the GrobClaims / VirtualKeyContext
    // are already populated; in axum the from_fn applied first becomes the
    // innermost layer, so it must be added before auth_middleware below.
    let app = app.layer(axum::middleware::from_fn_with_state(
        state.clone(),
        tenant_required_middleware,
    ));

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

    // A body-size limit of 0 means "unlimited" — skip the layer entirely so
    // large agentic contexts are not rejected (see `BodySizeLimit`).
    let app = if config.security.max_body_size.value() > 0 {
        app.layer(RequestBodyLimitLayer::new(
            config.security.max_body_size.value(),
        ))
    } else {
        app
    };

    // Audit middleware: captures every request lifecycle, including those
    // rejected by rate-limit / auth before reaching a handler. Layered
    // INSIDE `request_id_middleware` (which is added afterwards and so wraps
    // this one) so `RequestId` is set in extensions before the audit logic
    // reads it.
    let app = app.layer(axum::middleware::from_fn_with_state(
        state.clone(),
        audit_log_layer,
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

    // HTTP request tracing (tower-http), added outermost so the span covers the
    // whole middleware stack. It records ONLY the method and path — never the
    // `Authorization` header or request/response bodies (secrets / PII) — and
    // skips the probe and metrics endpoints to avoid scrape noise. The span is
    // quiet by default (DEBUG lifecycle events) but is exported by the OTel layer
    // when the `otel` feature is enabled.
    let app = app.layer(
        tower_http::trace::TraceLayer::new_for_http().make_span_with(
            |request: &axum::http::Request<axum::body::Body>| {
                let path = request.uri().path();
                if matches!(path, "/metrics" | "/health" | "/live" | "/ready") {
                    return tracing::Span::none();
                }
                tracing::info_span!(
                    "http_request",
                    method = %request.method(),
                    path = %path,
                )
            },
        ),
    );

    app.with_state(state)
}

// ── HIT Gateway approval endpoint ──

/// Request body for `POST /api/hit/approve`.
#[cfg(feature = "policies")]
#[derive(serde::Deserialize)]
struct HitApproveRequest {
    /// Correlation ID of the request that triggered the approval pause.
    request_id: String,
    /// Tool name to approve or deny.
    tool_name: String,
    /// Whether to approve (`true`) or deny (`false`) the tool call.
    approved: bool,
    /// Signer identity for multisig approvals (e.g. `"alice@company.com"`).
    /// Required when the pending entry is `MultiSig`.
    signer: Option<String>,
}

/// Resolves a pending HIT approval.
///
/// - `Simple`: first caller decides. Returns `200 OK`.
/// - `MultiSig`: submits one signature; returns `200 OK` when quorum reached, `202 Accepted` while collecting.
/// - `Quorum`: casts one vote; returns `200 OK` on decision, `202 Accepted` while gathering.
/// - `404 Not Found` if no pending entry matches `request_id`/`tool_name`.
#[cfg(feature = "policies")]
async fn hit_approve_handler(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    axum::Json(body): axum::Json<HitApproveRequest>,
) -> axum::http::StatusCode {
    use crate::features::policies::hit_auth::{
        AuthDecision, AuthMethod, HitAuthParams, HitAuthorization,
    };
    use crate::features::policies::multisig::MultiSigStatus;
    use crate::features::policies::quorum::{tally_votes, QuorumResult, VoterDecision};
    use crate::features::policies::stream::HitApprovalEntry;

    let key = format!("{}:{}", body.request_id, body.tool_name);
    let entry = state
        .hit_pending
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&key);

    match entry {
        None => axum::http::StatusCode::NOT_FOUND,

        Some(HitApprovalEntry::Simple(tx)) => {
            let _ = tx.send(body.approved);
            axum::http::StatusCode::OK
        }

        Some(HitApprovalEntry::MultiSig(mut multi)) => {
            let signer = body.signer.unwrap_or_else(|| "unknown".to_string());
            let prev_hash = multi.last_hash.take();
            let auth = HitAuthorization::new(HitAuthParams {
                request_id: body.request_id.clone(),
                tool_name: body.tool_name.clone(),
                tool_input: String::new(),
                decision: if body.approved {
                    AuthDecision::Approve
                } else {
                    AuthDecision::Deny
                },
                auth_method: AuthMethod::Multisig,
                signer,
                previous_hash: prev_hash,
            });
            multi.last_hash = Some(auth.hash.clone());
            match multi.collector.submit(auth) {
                MultiSigStatus::Complete => {
                    let _ = multi.sender.send(true);
                    axum::http::StatusCode::OK
                }
                MultiSigStatus::Rejected(reason) => {
                    tracing::info!(reason = %reason, "HIT multisig: rejected");
                    let _ = multi.sender.send(false);
                    axum::http::StatusCode::OK
                }
                MultiSigStatus::Pending {
                    received,
                    remaining,
                } => {
                    tracing::info!(
                        received = received,
                        remaining = remaining,
                        "HIT multisig: pending, re-inserting"
                    );
                    state
                        .hit_pending
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(key, HitApprovalEntry::MultiSig(multi));
                    axum::http::StatusCode::ACCEPTED
                }
            }
        }

        Some(HitApprovalEntry::Quorum(mut quorum)) => {
            let vote = if body.approved {
                VoterDecision::Approve
            } else {
                VoterDecision::Deny
            };
            quorum.votes.push(vote);
            match tally_votes(&quorum.config, &quorum.votes) {
                QuorumResult::Approve => {
                    let _ = quorum.sender.send(true);
                    axum::http::StatusCode::OK
                }
                QuorumResult::Deny => {
                    let _ = quorum.sender.send(false);
                    axum::http::StatusCode::OK
                }
                QuorumResult::Escalate => {
                    tracing::info!(
                        votes = quorum.votes.len(),
                        "HIT quorum: inconclusive, waiting for more votes"
                    );
                    state
                        .hit_pending
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(key, HitApprovalEntry::Quorum(quorum));
                    axum::http::StatusCode::ACCEPTED
                }
            }
        }
    }
}

/// Handles a JSON-RPC 2.0 request by resolving caller identity and dispatching.
async fn handle_rpc(
    state: Arc<AppState>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    // Parse the JSON-RPC envelope
    let req: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => {
            return axum::Json(serde_json::json!({
                "jsonrpc": "2.0",
                "error": { "code": -32700, "message": "Parse error" },
                "id": null
            }))
            .into_response();
        }
    };

    let id = req.get("id").cloned().unwrap_or(serde_json::Value::Null);
    let method = match req.get("method").and_then(|m| m.as_str()) {
        Some(m) => m,
        None => {
            return axum::Json(serde_json::json!({
                "jsonrpc": "2.0",
                "error": { "code": -32600, "message": "Invalid Request: missing method" },
                "id": id
            }))
            .into_response();
        }
    };
    let params = req.get("params");

    // Resolve caller identity
    let client_ip = extract_client_ip(&headers);
    let auth_header = extract_api_credential(&headers);
    let auth_mode = {
        let inner = state.snapshot();
        inner.config.auth.mode.clone()
    };

    let caller = match rpc::auth::resolve_caller(
        &client_ip,
        auth_header,
        &auth_mode,
        state.security.jwt_validator.as_deref(),
    ) {
        Ok(c) => c,
        Err(e) => {
            return axum::Json(serde_json::json!({
                "jsonrpc": "2.0",
                "error": { "code": e.code(), "message": e.message() },
                "id": id
            }))
            .into_response();
        }
    };

    // Audit the RPC call
    #[cfg(feature = "compliance")]
    if let Some(ref audit_log) = state.security.audit_log {
        let tenant = if caller.tenant_id.is_empty() {
            &caller.ip
        } else {
            &caller.tenant_id
        };
        let entry = AuditEntryBuilder::new(
            tenant,
            crate::security::audit_log::AuditEvent::ConfigChange,
            &format!("rpc:{method}"),
            &caller.ip,
            0,
        )
        .build();
        if let Err(e) = audit_log.write(entry) {
            tracing::error!(error = %e, "RPC audit write failed");
        }
    }

    // Dispatch to the appropriate handler
    match rpc::dispatch(&state, &caller, method, params).await {
        Ok(result) => axum::Json(serde_json::json!({
            "jsonrpc": "2.0",
            "result": result,
            "id": id
        }))
        .into_response(),
        Err(e) => axum::Json(serde_json::json!({
            "jsonrpc": "2.0",
            "error": { "code": e.code(), "message": e.message() },
            "id": id
        }))
        .into_response(),
    }
}

// ── Compile-time Send + Sync assertions ──
// Axum requires handler state to be Send + Sync + 'static.
// These assertions catch accidental regressions at compile time.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<AppState>();
    assert_send_sync::<ReloadableState>();
};

mod oauth_handlers;
mod openai_compat;

use crate::auth::TokenStore;
use crate::cli::AppConfig;
use crate::features::dlp::DlpEngine;
use std::borrow::Cow;
use crate::features::token_pricing::spend::SpendTracker;
use crate::features::token_pricing::{SharedPricingTable, TokenCounter};
use crate::message_tracing::MessageTracer;
use crate::models::{AnthropicRequest, RouteType};
use crate::providers::{AuthType, ProviderRegistry};
use crate::router::Router;
use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router as AxumRouter,
};
use bytes::Bytes;
use futures::stream::{Stream, TryStreamExt};
use std::pin::Pin;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};

/// Reloadable components - rebuilt on config reload
pub struct ReloadableState {
    pub config: AppConfig,
    pub router: Router,
    pub provider_registry: Arc<ProviderRegistry>,
    /// Pre-computed index: lowercase model name → index into config.models (O(1) lookup)
    pub model_index: std::collections::HashMap<String, usize>,
}

impl ReloadableState {
    fn new(config: AppConfig, router: Router, provider_registry: Arc<ProviderRegistry>) -> Self {
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

/// Application state shared across handlers
pub struct AppState {
    /// Reloadable state behind a single lock for atomic updates
    inner: std::sync::RwLock<Arc<ReloadableState>>,

    /// Persistent state - NOT reloaded
    pub token_store: TokenStore,
    pub config_source: crate::cli::ConfigSource,
    pub message_tracer: Arc<MessageTracer>,
    pub metrics_handle: metrics_exporter_prometheus::PrometheusHandle,
    pub active_requests: std::sync::atomic::AtomicU64,

    /// Spend tracker (budget enforcement)
    pub spend_tracker: std::sync::Mutex<SpendTracker>,
    /// Dynamic pricing table (refreshed from OpenRouter every 24h)
    pub pricing_table: SharedPricingTable,
    /// DLP engine (None if disabled)
    pub dlp_engine: Option<Arc<DlpEngine>>,
}

impl AppState {
    /// Get a snapshot of current reloadable state
    pub fn snapshot(&self) -> Arc<ReloadableState> {
        self.inner.read().unwrap().clone()
    }
}

/// Auth middleware: checks Bearer token or x-api-key against server.api_key config.
/// Skips auth for health/metrics/oauth paths. If api_key is not configured, all requests pass.
/// Constant-time string comparison to prevent timing side-channel attacks
fn constant_time_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    // Skip auth for operational/oauth paths
    let path = request.uri().path();
    if matches!(
        path,
        "/health" | "/metrics" | "/auth/callback" | "/api/oauth/callback"
    ) {
        return next.run(request).await;
    }

    let inner = state.snapshot();
    let api_key = inner.config.server.api_key.as_deref().unwrap_or("");
    if api_key.is_empty() {
        return next.run(request).await;
    }

    // Check Authorization: Bearer <token> or x-api-key: <token>
    let token = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .or_else(|| {
            request
                .headers()
                .get("x-api-key")
                .and_then(|v| v.to_str().ok())
        });

    match token {
        Some(t) if constant_time_eq(t, api_key) => next.run(request).await,
        _ => {
            let body = Json(serde_json::json!({
                "error": {
                    "type": "authentication_error",
                    "message": "Invalid or missing API key. Provide via Authorization: Bearer <key> or x-api-key header."
                }
            }));
            (StatusCode::UNAUTHORIZED, body).into_response()
        }
    }
}

/// Start the HTTP server
pub async fn start_server(
    config: AppConfig,
    config_source: crate::cli::ConfigSource,
) -> anyhow::Result<()> {
    let router = Router::new(config.clone());

    // Initialize OAuth token store FIRST (needed by provider registry)
    let token_store = TokenStore::at_default_path()
        .map_err(|e| anyhow::anyhow!("Failed to initialize token store: {}", e))?;

    let existing_tokens = token_store.list_providers();
    if !existing_tokens.is_empty() {
        info!(
            "🔐 Loaded {} OAuth tokens from storage",
            existing_tokens.len()
        );
    }

    // Initialize provider registry from config (with token store and model mappings)
    let provider_registry = Arc::new(
        ProviderRegistry::from_configs_with_models(
            &config.providers,
            Some(token_store.clone()),
            &config.models,
        )
        .map_err(|e| anyhow::anyhow!("Failed to initialize provider registry: {}", e))?,
    );

    info!(
        "📦 Loaded {} providers with {} models",
        provider_registry.list_providers().len(),
        provider_registry.list_models().len()
    );

    // Validate providers and models with real API calls (non-blocking)
    {
        let config_ref = config.clone();
        let registry_ref = provider_registry.clone();
        tokio::spawn(async move {
            info!("🔍 Validating providers and models...");
            let results = crate::preset::validate_config(&config_ref, &registry_ref).await;
            crate::preset::log_validation_results(&results);

            let total = results.len();
            let healthy = results.iter().filter(|r| r.any_ok()).count();
            if healthy == total {
                info!(
                    "✅ Validation complete: {}/{} models healthy",
                    healthy, total
                );
            } else {
                error!(
                    "⚠️ Validation: {}/{} models healthy — some models will fail at runtime",
                    healthy, total
                );
            }
        });
    }

    // Initialize message tracer
    let message_tracer = Arc::new(MessageTracer::new(config.server.tracing.clone()));

    // Initialize spend tracker
    let spend_tracker = SpendTracker::load(SpendTracker::default_path());
    if spend_tracker.total() > 0.0 {
        info!(
            "💰 Loaded spend tracker: ${:.2} spent this month",
            spend_tracker.total()
        );
    }

    // Initialize dynamic pricing table (fetches from OpenRouter)
    let pricing_table = crate::features::token_pricing::init_pricing_table().await;

    // Install Prometheus metrics recorder
    let prometheus_builder = metrics_exporter_prometheus::PrometheusBuilder::new();
    let metrics_handle = prometheus_builder
        .install_recorder()
        .map_err(|e| anyhow::anyhow!("Failed to install Prometheus recorder: {}", e))?;

    // Initialize DLP engine (if enabled in config)
    let dlp_engine = DlpEngine::from_config(config.dlp.clone());

    // Build reloadable state
    let reloadable = Arc::new(ReloadableState::new(config.clone(), router, provider_registry));

    let state = Arc::new(AppState {
        inner: std::sync::RwLock::new(reloadable),
        token_store,
        config_source,
        message_tracer,
        metrics_handle,
        active_requests: std::sync::atomic::AtomicU64::new(0),
        spend_tracker: std::sync::Mutex::new(spend_tracker),
        pricing_table,
        dlp_engine,
    });

    // Spawn background preset sync if configured and auto_sync is enabled
    if config.presets.auto_sync {
        if let Some(ref sync_url) = config.presets.sync_url {
            // Initial sync
            info!("🔄 Initial preset sync from {}...", sync_url);
            match crate::preset::sync_presets(sync_url).await {
                Ok(_) => info!("✅ Initial preset sync complete"),
                Err(e) => error!("⚠️ Initial preset sync failed: {}", e),
            }

            // Periodic sync if interval configured
            if let Some(ref interval) = config.presets.sync_interval {
                crate::preset::spawn_background_sync(sync_url.clone(), interval.clone());
            }
        }
    }

    // Build router
    let app = AxumRouter::new()
        // LLM API endpoints
        .route("/v1/messages", post(handle_messages))
        .route("/v1/messages/count_tokens", post(handle_count_tokens))
        .route("/v1/chat/completions", post(handle_openai_chat_completions))
        .route("/v1/models", get(handle_openai_models))
        // Operational endpoints
        .route("/health", get(health_check))
        .route("/metrics", get(metrics_endpoint))
        // Config management
        .route("/api/config", get(get_config_json))
        .route("/api/config", post(update_config_json))
        .route("/api/config/reload", post(reload_config))
        // OAuth endpoints
        .route(
            "/api/oauth/authorize",
            post(oauth_handlers::oauth_authorize),
        )
        .route("/api/oauth/exchange", post(oauth_handlers::oauth_exchange))
        .route("/api/oauth/callback", get(oauth_handlers::oauth_callback))
        .route("/auth/callback", get(oauth_handlers::oauth_callback)) // OpenAI Codex uses this path
        .route("/api/oauth/tokens", get(oauth_handlers::oauth_list_tokens))
        .route(
            "/api/oauth/tokens/delete",
            post(oauth_handlers::oauth_delete_token),
        )
        .route(
            "/api/oauth/tokens/refresh",
            post(oauth_handlers::oauth_refresh_token),
        );

    // Add auth middleware
    let app = app.layer(axum::middleware::from_fn_with_state(
        state.clone(),
        auth_middleware,
    ));

    // Clone state before moving it
    let oauth_state = state.clone();
    let app = app.with_state(state);

    // Bind to main address
    let addr = format!("{}:{}", config.server.host, config.server.port);
    let listener = TcpListener::bind(&addr).await?;

    info!("🚀 Server listening on {}", addr);

    // Start OAuth callback server on port 1455 (required for OpenAI Codex)
    // This is necessary because OpenAI's OAuth app only allows localhost:1455/auth/callback
    tokio::spawn(async move {
        let oauth_callback_app = AxumRouter::new()
            .route("/auth/callback", get(oauth_handlers::oauth_callback))
            .with_state(oauth_state);

        let oauth_addr = "127.0.0.1:1455";
        match TcpListener::bind(oauth_addr).await {
            Ok(oauth_listener) => {
                info!("🔐 OAuth callback server listening on {}", oauth_addr);
                if let Err(e) = axum::serve(oauth_listener, oauth_callback_app).await {
                    error!("OAuth callback server error: {}", e);
                }
            }
            Err(e) => {
                // Don't fail if port 1455 is already in use - just warn
                error!(
                    "⚠️  Failed to bind OAuth callback server on {}: {}",
                    oauth_addr, e
                );
                error!("⚠️  OpenAI Codex OAuth will not work. Port 1455 must be available.");
            }
        }
    });

    // Start main server
    axum::serve(listener, app).await?;

    Ok(())
}

/// Health check endpoint
async fn health_check(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let active = state
        .active_requests
        .load(std::sync::atomic::Ordering::Relaxed);
    let spend_total = {
        let tracker = state.spend_tracker.lock().unwrap();
        tracker.total()
    };
    let inner = state.snapshot();
    let budget_limit = inner.config.budget.monthly_limit_usd;
    Json(serde_json::json!({
        "status": "ok",
        "service": "grob",
        "active_requests": active,
        "spend": {
            "total_usd": spend_total,
            "budget_usd": budget_limit,
        }
    }))
}

/// Prometheus metrics endpoint
async fn metrics_endpoint(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let active = state
        .active_requests
        .load(std::sync::atomic::Ordering::Relaxed);
    metrics::gauge!("grob_active_requests").set(active as f64);

    // Publish spend/budget gauges (point-in-time snapshots → gauges are correct)
    let inner = state.snapshot();
    let tracker = state.spend_tracker.lock().unwrap();
    metrics::gauge!("grob_spend_usd").set(tracker.total());
    let budget_limit = inner.config.budget.monthly_limit_usd;
    if budget_limit > 0.0 {
        metrics::gauge!("grob_budget_limit_usd").set(budget_limit);
        metrics::gauge!("grob_budget_remaining_usd").set((budget_limit - tracker.total()).max(0.0));
    }
    drop(tracker);

    let body = state.metrics_handle.render();
    Response::builder()
        .header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        .body(Body::from(body))
        .unwrap()
}

/// Drop guard that decrements the active request counter
struct ActiveRequestGuard(Arc<AppState>);

impl ActiveRequestGuard {
    fn new(state: &Arc<AppState>) -> Self {
        state
            .active_requests
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Self(Arc::clone(state))
    }
}

impl Drop for ActiveRequestGuard {
    fn drop(&mut self) {
        self.0
            .active_requests
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Redact an API key for safe display (show first 4 + last 4 chars)
fn redact_api_key(key: &str) -> String {
    if key.starts_with('$') {
        return key.to_string(); // Environment variable reference, safe to show
    }
    if key.len() <= 12 {
        return "***".to_string();
    }
    format!("{}...{}", &key[..4], &key[key.len() - 4..])
}

/// Get full configuration as JSON — API keys are redacted
async fn get_config_json(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let inner = state.snapshot();

    // Redact API keys before serializing
    let providers: Vec<serde_json::Value> = inner
        .config
        .providers
        .iter()
        .map(|p| {
            let mut v = serde_json::to_value(p).unwrap_or_default();
            if let Some(obj) = v.as_object_mut() {
                if let Some(key) = obj.get("api_key").and_then(|k| k.as_str()) {
                    obj.insert(
                        "api_key".to_string(),
                        serde_json::Value::String(redact_api_key(key)),
                    );
                }
            }
            v
        })
        .collect();

    Json(serde_json::json!({
        "server": {
            "host": inner.config.server.host,
            "port": inner.config.server.port,
        },
        "router": {
            "default": inner.config.router.default,
            "background": inner.config.router.background,
            "think": inner.config.router.think,
            "websearch": inner.config.router.websearch,
            "auto_map_regex": inner.config.router.auto_map_regex,
            "background_regex": inner.config.router.background_regex,
            "prompt_rules": inner.config.router.prompt_rules,
        },
        "providers": providers,
        "models": inner.config.models,
    }))
}

/// Remove null values from JSON (TOML doesn't support null)
fn remove_null_values(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            map.retain(|_, v| !v.is_null());
            for (_, v) in map.iter_mut() {
                remove_null_values(v);
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr.iter_mut() {
                remove_null_values(item);
            }
        }
        _ => {}
    }
}

/// Update configuration via JSON
async fn update_config_json(
    State(state): State<Arc<AppState>>,
    Json(mut new_config): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Remove null values (TOML doesn't support null)
    remove_null_values(&mut new_config);

    // Write back to config file (only works with local file configs)
    let config_path = match &state.config_source {
        crate::cli::ConfigSource::File(p) => p,
        crate::cli::ConfigSource::Url(_) => {
            return Err(AppError::ParseError(
                "Cannot save config: loaded from remote URL (read-only)".to_string(),
            ));
        }
    };

    // Read current config
    let config_str = std::fs::read_to_string(config_path)
        .map_err(|e| AppError::ParseError(format!("Failed to read config: {}", e)))?;

    let mut config: toml::Value = toml::from_str(&config_str)
        .map_err(|e| AppError::ParseError(format!("Failed to parse config: {}", e)))?;

    // Update providers section
    if let Some(providers) = new_config.get("providers") {
        // Convert from serde_json::Value to toml::Value
        let providers_toml: toml::Value = serde_json::from_str(&providers.to_string())
            .map_err(|e| AppError::ParseError(format!("Failed to convert providers: {}", e)))?;

        if let Some(table) = config.as_table_mut() {
            table.insert("providers".to_string(), providers_toml);
        }
    }

    // Update models section
    if let Some(models) = new_config.get("models") {
        // Convert from serde_json::Value to toml::Value
        let models_toml: toml::Value = serde_json::from_str(&models.to_string())
            .map_err(|e| AppError::ParseError(format!("Failed to convert models: {}", e)))?;

        if let Some(table) = config.as_table_mut() {
            table.insert("models".to_string(), models_toml);
        }
    }

    // Update router section if provided
    if let Some(router) = new_config.get("router") {
        if let Some(router_table) = config.get_mut("router").and_then(|v| v.as_table_mut()) {
            // Helper to update or remove a router field
            let update_field = |table: &mut toml::map::Map<String, toml::Value>,
                                key: &str,
                                value: Option<&serde_json::Value>| {
                if let Some(val) = value {
                    if let Some(s) = val.as_str() {
                        table.insert(key.to_string(), toml::Value::String(s.to_string()));
                    }
                } else {
                    // Remove field if not present in incoming config
                    table.remove(key);
                }
            };

            // Default is required, always update if present
            if let Some(default) = router.get("default") {
                if let Some(s) = default.as_str() {
                    router_table.insert("default".to_string(), toml::Value::String(s.to_string()));
                }
            }

            // Optional fields - remove if not present
            update_field(router_table, "think", router.get("think"));
            update_field(router_table, "websearch", router.get("websearch"));
            update_field(router_table, "background", router.get("background"));
            update_field(router_table, "auto_map_regex", router.get("auto_map_regex"));
            update_field(
                router_table,
                "background_regex",
                router.get("background_regex"),
            );
        }
    }

    // Write back to file
    let new_config_str = toml::to_string_pretty(&config)
        .map_err(|e| AppError::ParseError(format!("Failed to serialize config: {}", e)))?;

    std::fs::write(config_path, new_config_str)
        .map_err(|e| AppError::ParseError(format!("Failed to write config: {}", e)))?;

    info!("✅ Configuration updated successfully via API");

    Ok(Json(serde_json::json!({
        "status": "success",
        "message": "Configuration saved successfully"
    })))
}

/// Reload configuration without restarting the server
async fn reload_config(State(state): State<Arc<AppState>>) -> Response {
    info!("🔄 Configuration reload requested via UI");

    // 1. Read and parse new config from source
    let new_config: AppConfig = match AppConfig::from_source(&state.config_source).await {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to reload config: {}", e);
            return Json(serde_json::json!({"status": "error", "message": format!("Failed to reload config: {}", e)})).into_response();
        }
    };

    // 2. Build new router (compiles regexes)
    let new_router = Router::new(new_config.clone());

    // 3. Build new provider registry (reuse existing token_store)
    let new_registry = match ProviderRegistry::from_configs_with_models(
        &new_config.providers,
        Some(state.token_store.clone()),
        &new_config.models,
    ) {
        Ok(r) => Arc::new(r),
        Err(e) => {
            error!("Failed to init providers: {}", e);
            return Json(serde_json::json!({"status": "error", "message": format!("Failed to init providers: {}", e)})).into_response();
        }
    };

    // 4. Create new reloadable state
    let new_inner = Arc::new(ReloadableState::new(new_config, new_router, new_registry));

    // 5. Atomic swap (write lock held for microseconds)
    let active = state
        .active_requests
        .load(std::sync::atomic::Ordering::Relaxed);
    *state.inner.write().unwrap() = new_inner.clone();

    if active > 0 {
        info!(
            "✅ Configuration reloaded successfully ({} requests still using old config)",
            active
        );
    } else {
        info!("✅ Configuration reloaded successfully");
    }

    // 6. Validate new config in background (non-blocking)
    tokio::spawn(async move {
        info!("🔍 Validating reloaded config...");
        let results =
            crate::preset::validate_config(&new_inner.config, &new_inner.provider_registry).await;
        crate::preset::log_validation_results(&results);
    });

    Json(serde_json::json!({"status": "success", "message": "Configuration reloaded", "active_requests": active})).into_response()
}

/// Record Prometheus metrics for a completed request.
///
/// Naming follows Prometheus/OpenMetrics conventions:
/// - Counters end with `_total`
/// - Units in metric name as suffix (`_seconds`, `_usd`)
/// - No label names embedded in metric names
#[allow(clippy::too_many_arguments)]
fn record_request_metrics(
    model: &str,
    provider: &str,
    route_type: &RouteType,
    status: &str,
    latency_ms: u64,
    input_tokens: u32,
    output_tokens: u32,
    cost_usd: f64,
) {
    // Allocate label strings once and reuse across all metric calls
    let m = model.to_string();
    let p = provider.to_string();
    let rt = route_type.to_string();
    let s = status.to_string();
    metrics::counter!("grob_requests_total",
        "model" => m.clone(), "provider" => p.clone(), "route_type" => rt, "status" => s
    ).increment(1);
    metrics::histogram!("grob_request_duration_seconds",
        "model" => m.clone(), "provider" => p.clone()
    )
    .record(latency_ms as f64 / 1000.0);
    metrics::counter!("grob_input_tokens_total",
        "model" => m.clone(), "provider" => p.clone()
    )
    .increment(input_tokens as u64);
    metrics::counter!("grob_output_tokens_total",
        "model" => m.clone(), "provider" => p.clone()
    )
    .increment(output_tokens as u64);
    if cost_usd > 0.0 {
        // Gauge used as monotonic accumulator (Counter only supports u64,
        // but cost is fractional USD). Supports rate() in PromQL.
        // Month-to-date persistent total is in grob_spend_usd (set in /metrics).
        metrics::gauge!("grob_request_cost_usd",
            "model" => m, "provider" => p
        )
        .increment(cost_usd);
    }
}

/// Check budget before a request. Returns Err(AppError::BudgetExceeded) if any limit is hit.
fn check_budget(
    state: &Arc<AppState>,
    inner: &Arc<ReloadableState>,
    provider_name: &str,
    model_name: &str,
) -> Result<(), AppError> {
    let budget_config = &inner.config.budget;
    let global_limit = budget_config.monthly_limit_usd;

    // Find provider and model budget limits
    let provider_limit = inner
        .config
        .providers
        .iter()
        .find(|p| p.name == provider_name)
        .and_then(|p| p.budget_usd);

    let model_limit = inner.find_model(model_name).and_then(|m| m.budget_usd);

    let tracker = state.spend_tracker.lock().unwrap();

    // Check budget
    if let Err(e) = tracker.check_budget(
        provider_name,
        model_name,
        global_limit,
        provider_limit,
        model_limit,
    ) {
        return Err(AppError::BudgetExceeded(e.message));
    }

    // Check warnings
    if let Some(warning) = tracker.check_warnings(
        provider_name,
        model_name,
        global_limit,
        provider_limit,
        model_limit,
        budget_config.warn_at_percent,
    ) {
        warn!("Budget warning: {}", warning);
    }

    Ok(())
}

/// Record spend after a successful request
fn record_spend(state: &Arc<AppState>, provider_name: &str, model_name: &str, cost: f64) {
    if cost > 0.0 {
        let mut tracker = state.spend_tracker.lock().unwrap();
        tracker.record(provider_name, model_name, cost);
    }
}

/// Check if a provider uses OAuth (subscription = $0 cost)
fn is_provider_subscription(inner: &Arc<ReloadableState>, provider_name: &str) -> bool {
    inner
        .config
        .providers
        .iter()
        .find(|p| p.name == provider_name)
        .map(|p| p.auth_type == AuthType::OAuth)
        .unwrap_or(false)
}

/// Calculate cost using dynamic pricing table
async fn calculate_cost(
    state: &Arc<AppState>,
    actual_model: &str,
    input_tokens: u32,
    output_tokens: u32,
    is_subscription: bool,
) -> TokenCounter {
    let table = state.pricing_table.read().await;
    TokenCounter::with_pricing(
        actual_model,
        input_tokens,
        output_tokens,
        is_subscription,
        Some(&table),
    )
}

/// Handle /v1/chat/completions requests (OpenAI-compatible endpoint)
/// Supports both streaming (SSE) and non-streaming responses, plus tool calling.
async fn handle_openai_chat_completions(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(openai_request): Json<openai_compat::OpenAIRequest>,
) -> Result<Response, AppError> {
    let _guard = ActiveRequestGuard::new(&state);
    let model = openai_request.model.clone();
    let is_streaming = openai_request.stream == Some(true);
    let start_time = std::time::Instant::now();

    // Get snapshot of reloadable state
    let inner = state.snapshot();

    // 1. Transform OpenAI request to Anthropic format
    let mut anthropic_request = openai_compat::transform_openai_to_anthropic(openai_request)
        .map_err(|e| AppError::ParseError(format!("Failed to transform OpenAI request: {}", e)))?;

    // 2. Route the request
    let decision = inner
        .router
        .route(&mut anthropic_request)
        .map_err(|e| AppError::RoutingError(e.to_string()))?;

    // Resolve provider list
    let sorted_mappings = resolve_provider_mappings(&inner, &headers, &decision)?;

    // 3. Try each mapping in priority order
    for (idx, mapping) in sorted_mappings.iter().enumerate() {
        let Some(provider) = inner.provider_registry.get_provider(&mapping.provider) else {
            info!(
                "⚠️ Provider {} not found in registry, trying next fallback",
                mapping.provider
            );
            continue;
        };

        // Budget check before sending request
        check_budget(&state, &inner, &mapping.provider, &decision.model_name)?;

        let retry_info = if idx > 0 {
            format!(" [{}/{}]", idx + 1, sorted_mappings.len())
        } else {
            String::new()
        };
        let stream_mode = if is_streaming { "stream" } else { "sync" };
        let route_type_display = format_route_type(&decision);

        info!(
            "[{:<15}:{}] {:<25} → {}/{}{}",
            route_type_display,
            stream_mode,
            model,
            mapping.provider,
            mapping.actual_model,
            retry_info
        );

        // Update model to actual model name
        anthropic_request.model = mapping.actual_model.clone();

        // DLP: sanitize request (names → pseudonyms, secrets → canary)
        if let Some(ref dlp) = state.dlp_engine {
            if dlp.config.scan_input {
                dlp.sanitize_request(&mut anthropic_request);
            }
        }

        // Inject continuation prompt if configured
        if mapping.inject_continuation_prompt && decision.route_type != RouteType::Background {
            if let Some(last_msg) = anthropic_request.messages.last_mut() {
                if should_inject_continuation(last_msg) {
                    info!(
                        "💉 Injecting continuation prompt for model: {}",
                        mapping.actual_model
                    );
                    inject_continuation_text(last_msg);
                }
            }
        }

        let is_sub = is_provider_subscription(&inner, &mapping.provider);

        if is_streaming {
            // ── Streaming path ──
            match provider
                .send_message_stream(anthropic_request.clone())
                .await
            {
                Ok(stream_response) => {
                    // Wrap stream with DLP if enabled for output scanning
                    let stream: Pin<Box<dyn Stream<Item = Result<Bytes, crate::providers::error::ProviderError>> + Send>> =
                        if let Some(ref dlp) = state.dlp_engine {
                            if dlp.config.scan_output {
                                Box::pin(crate::features::dlp::stream::DlpStream::new(
                                    stream_response.stream,
                                    Arc::clone(dlp),
                                ))
                            } else {
                                stream_response.stream
                            }
                        } else {
                            stream_response.stream
                        };

                    // Wrap Anthropic SSE → OpenAI SSE
                    let mut transformer =
                        openai_compat::AnthropicToOpenAIStream::new(model.clone());
                    let mapped = stream
                        .map_ok(move |bytes| transformer.transform_bytes(&bytes))
                        .try_filter(|b| futures::future::ready(!b.is_empty()));

                    let body =
                        Body::from_stream(mapped.map_err(|e| std::io::Error::other(e.to_string())));

                    let response = Response::builder()
                        .status(200)
                        .header("Content-Type", "text/event-stream")
                        .header("Cache-Control", "no-cache")
                        .header("Connection", "keep-alive")
                        .body(body)
                        .unwrap();

                    return Ok(response);
                }
                Err(e) => {
                    let is_rate_limit = matches!(
                        &e,
                        crate::providers::error::ProviderError::ApiError { status: 429, .. }
                    );
                    if is_rate_limit {
                        warn!("Provider {} rate limited, falling back", mapping.provider);
                        metrics::counter!("grob_ratelimit_hits_total", "provider" => mapping.provider.clone()).increment(1);
                    }
                    metrics::counter!("grob_provider_errors_total", "provider" => mapping.provider.clone()).increment(1);
                    info!(
                        "⚠️ Provider {} streaming failed: {}, trying next fallback",
                        mapping.provider, e
                    );
                    continue;
                }
            }
        } else {
            // ── Non-streaming path ──
            match provider.send_message(anthropic_request.clone()).await {
                Ok(mut anthropic_response) => {
                    let latency_ms = start_time.elapsed().as_millis() as u64;
                    let tok_s = (anthropic_response.usage.output_tokens as f32 * 1000.0)
                        / latency_ms as f32;
                    let cost = calculate_cost(
                        &state,
                        &mapping.actual_model,
                        anthropic_response.usage.input_tokens,
                        anthropic_response.usage.output_tokens,
                        is_sub,
                    )
                    .await;
                    info!(
                        "📊 {}@{} {}ms {:.0}t/s {}tok ${:.4}{}",
                        mapping.actual_model,
                        mapping.provider,
                        latency_ms,
                        tok_s,
                        anthropic_response.usage.output_tokens,
                        cost.estimated_cost_usd,
                        if is_sub { " (subscription)" } else { "" }
                    );

                    record_request_metrics(
                        &mapping.actual_model,
                        &mapping.provider,
                        &decision.route_type,
                        "ok",
                        latency_ms,
                        anthropic_response.usage.input_tokens,
                        anthropic_response.usage.output_tokens,
                        cost.estimated_cost_usd,
                    );

                    // Record spend for budget tracking
                    record_spend(
                        &state,
                        &mapping.provider,
                        &decision.model_name,
                        cost.estimated_cost_usd,
                    );

                    // DLP: sanitize response (deanonymize names, scan secrets)
                    if let Some(ref dlp) = state.dlp_engine {
                        if dlp.config.scan_output {
                            sanitize_provider_response(&mut anthropic_response, dlp);
                        }
                    }

                    let openai_response = openai_compat::transform_anthropic_to_openai(
                        anthropic_response,
                        model.clone(),
                    );
                    return Ok(Json(openai_response).into_response());
                }
                Err(e) => {
                    let is_rate_limit = matches!(
                        &e,
                        crate::providers::error::ProviderError::ApiError { status: 429, .. }
                    );
                    if is_rate_limit {
                        warn!("Provider {} rate limited, falling back", mapping.provider);
                        metrics::counter!("grob_ratelimit_hits_total", "provider" => mapping.provider.clone()).increment(1);
                    }
                    metrics::counter!("grob_provider_errors_total", "provider" => mapping.provider.clone()).increment(1);
                    info!(
                        "⚠️ Provider {} failed: {}, trying next fallback",
                        mapping.provider, e
                    );
                    continue;
                }
            }
        }
    }

    error!(
        "❌ All provider mappings failed for model: {}",
        decision.model_name
    );
    Err(AppError::ProviderError(format!(
        "All {} provider mappings failed for model: {}",
        sorted_mappings.len(),
        decision.model_name
    )))
}

/// Resolve and sort provider mappings for a routing decision.
fn resolve_provider_mappings(
    inner: &Arc<ReloadableState>,
    headers: &HeaderMap,
    decision: &crate::models::RouteDecision,
) -> Result<Vec<crate::cli::ModelMapping>, AppError> {
    if let Some(model_config) = inner.find_model(&decision.model_name) {
        let forced_provider = headers
            .get("x-provider")
            .and_then(|v| v.to_str().ok())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());

        if let Some(ref provider_name) = forced_provider {
            info!(
                "🎯 Using forced provider from X-Provider header: {}",
                provider_name
            );
        }

        let mut sorted = model_config.mappings.clone();
        if let Some(ref provider_name) = forced_provider {
            sorted.retain(|m| m.provider == *provider_name);
            if sorted.is_empty() {
                return Err(AppError::RoutingError(format!(
                    "Provider '{}' not found in mappings for model '{}'",
                    provider_name, decision.model_name
                )));
            }
        } else {
            sorted.sort_by_key(|m| m.priority);
        }
        Ok(sorted)
    } else {
        Err(AppError::ProviderError(format!(
            "No model mapping found for model: {}",
            decision.model_name
        )))
    }
}

/// Apply DLP sanitization to a non-streaming provider response.
fn sanitize_provider_response(
    response: &mut crate::providers::ProviderResponse,
    dlp: &Arc<DlpEngine>,
) {
    use crate::models::{ContentBlock, KnownContentBlock};
    for block in &mut response.content {
        if let ContentBlock::Known(KnownContentBlock::Text { text, .. }) = block {
            if let Cow::Owned(s) = dlp.sanitize_response_text(text) {
                *text = s;
            }
        }
    }
}

/// Format route type for logging
fn format_route_type(decision: &crate::models::RouteDecision) -> String {
    match &decision.matched_prompt {
        Some(matched) => {
            let trimmed = if matched.len() > 30 {
                format!("{}...", &matched[..27])
            } else {
                matched.clone()
            };
            format!("{}:{}", decision.route_type, trimmed)
        }
        None => decision.route_type.to_string(),
    }
}

/// Handle /v1/models endpoint (OpenAI-compatible)
async fn handle_openai_models(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let inner = state.snapshot();
    let models: Vec<serde_json::Value> = inner
        .config
        .models
        .iter()
        .map(|m| {
            serde_json::json!({
                "id": m.name,
                "object": "model",
                "created": 0,
                "owned_by": "grob"
            })
        })
        .collect();
    Json(serde_json::json!({ "object": "list", "data": models }))
}

/// Check if message has tool results but no text content
/// (indicates model should continue after tool execution)
fn should_inject_continuation(msg: &crate::models::Message) -> bool {
    use crate::models::MessageContent;
    let has_tool_results = match &msg.content {
        MessageContent::Blocks(blocks) => blocks.iter().any(|b| b.is_tool_result()),
        _ => false,
    };

    let has_text = match &msg.content {
        MessageContent::Text(text) => !text.trim().is_empty(),
        MessageContent::Blocks(blocks) => blocks
            .iter()
            .any(|b| b.as_text().map(|t| !t.trim().is_empty()).unwrap_or(false)),
    };

    // Inject if message has tool results but no text
    has_tool_results && !has_text
}

/// Inject continuation text into the last user message
/// Prepends a text block to the existing message content (doesn't create a new message)
fn inject_continuation_text(msg: &mut crate::models::Message) {
    use crate::models::{ContentBlock, MessageContent};

    let continuation = "<system-reminder>If you have an active todo list, remember to mark items complete and continue to the next. Do not mention this reminder.</system-reminder>";

    match &mut msg.content {
        MessageContent::Text(text) => {
            // Convert to Blocks and prepend continuation
            let original_text = text.clone();
            msg.content = MessageContent::Blocks(vec![
                ContentBlock::text(continuation.to_string(), None),
                ContentBlock::text(original_text, None),
            ]);
        }
        MessageContent::Blocks(blocks) => {
            // Prepend continuation text to existing blocks
            blocks.insert(0, ContentBlock::text(continuation.to_string(), None));
        }
    }
}

/// Handle /v1/messages requests (both streaming and non-streaming)
async fn handle_messages(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request_json): Json<serde_json::Value>,
) -> Result<Response, AppError> {
    let _guard = ActiveRequestGuard::new(&state);
    let model = request_json
        .get("model")
        .and_then(|m| m.as_str())
        .unwrap_or("unknown");
    let start_time = std::time::Instant::now();

    // Get snapshot of reloadable state
    let inner = state.snapshot();

    // Generate trace ID for correlating request/response
    let trace_id = state.message_tracer.new_trace_id();

    // DEBUG: Log request body for debugging
    if let Ok(json_str) = serde_json::to_string_pretty(&request_json) {
        tracing::debug!("📥 Incoming request body:\n{}", json_str);
    }

    // 1. Parse request for routing decision (mutable for tag extraction)
    let mut request_for_routing: AnthropicRequest = serde_json::from_value(request_json.clone())
        .map_err(|e| {
            // Log the full request on parse failure for debugging
            if let Ok(pretty) = serde_json::to_string_pretty(&request_json) {
                tracing::error!(
                    "❌ Failed to parse request: {}\n📋 Request body:\n{}",
                    e,
                    pretty
                );
            } else {
                tracing::error!("❌ Failed to parse request: {}", e);
            }
            AppError::ParseError(format!("Invalid request format: {}", e))
        })?;

    // 2. Route the request (may modify system prompt to remove CCM-SUBAGENT-MODEL tag)
    let decision = inner
        .router
        .route(&mut request_for_routing)
        .map_err(|e| AppError::RoutingError(e.to_string()))?;

    // 3. Try model mappings with fallback (1:N mapping)
    if let Some(model_config) = inner.find_model(&decision.model_name) {
        // Check for X-Provider header to override priority
        let forced_provider = headers
            .get("x-provider")
            .and_then(|v| v.to_str().ok())
            .filter(|s| !s.is_empty()) // Ignore empty strings
            .map(|s| s.to_string());

        if let Some(ref provider_name) = forced_provider {
            info!(
                "🎯 Using forced provider from X-Provider header: {}",
                provider_name
            );
        }

        // Sort mappings by priority (or filter by forced provider)
        let mut sorted_mappings = model_config.mappings.clone();

        if let Some(ref provider_name) = forced_provider {
            // Filter to only the specified provider
            sorted_mappings.retain(|m| m.provider == *provider_name);
            if sorted_mappings.is_empty() {
                return Err(AppError::RoutingError(format!(
                    "Provider '{}' not found in mappings for model '{}'",
                    provider_name, decision.model_name
                )));
            }
        } else {
            // Use priority ordering
            sorted_mappings.sort_by_key(|m| m.priority);
        }

        // Try each mapping in priority order (or just the forced one)
        for (idx, mapping) in sorted_mappings.iter().enumerate() {
            // Try to get provider from registry
            if let Some(provider) = inner.provider_registry.get_provider(&mapping.provider) {
                // Budget check before sending request
                check_budget(&state, &inner, &mapping.provider, &decision.model_name)?;

                // Clone the already-parsed request (struct clone, not JSON re-parse)
                let mut anthropic_request = request_for_routing.clone();

                // Save original model name for response
                let original_model = anthropic_request.model.clone();

                // Update model to actual model name
                anthropic_request.model = mapping.actual_model.clone();

                // DLP: sanitize request (names → pseudonyms, secrets → canary)
                if let Some(ref dlp) = state.dlp_engine {
                    if dlp.config.scan_input {
                        dlp.sanitize_request(&mut anthropic_request);
                    }
                }

                // Inject continuation prompt if configured (skip for background tasks)
                if mapping.inject_continuation_prompt
                    && decision.route_type != RouteType::Background
                {
                    if let Some(last_msg) = anthropic_request.messages.last_mut() {
                        if should_inject_continuation(last_msg) {
                            info!(
                                "💉 Injecting continuation prompt for model: {}",
                                mapping.actual_model
                            );
                            inject_continuation_text(last_msg);
                        }
                    }
                }

                // Check if streaming is requested
                let is_streaming = anthropic_request.stream == Some(true);
                let is_sub = is_provider_subscription(&inner, &mapping.provider);

                // Build retry indicator (only show if not first attempt)
                let retry_info = if idx > 0 {
                    format!(" [{}/{}]", idx + 1, sorted_mappings.len())
                } else {
                    String::new()
                };

                let stream_mode = if is_streaming { "stream" } else { "sync" };

                // Build route type display (include matched prompt snippet if available)
                let route_type_display = match &decision.matched_prompt {
                    Some(matched) => {
                        // Trim prompt to max 30 chars
                        let trimmed = if matched.len() > 30 {
                            format!("{}...", &matched[..27])
                        } else {
                            matched.clone()
                        };
                        format!("{}:{}", decision.route_type, trimmed)
                    }
                    None => decision.route_type.to_string(),
                };

                info!(
                    "[{:<15}:{}] {:<25} → {}/{}{}",
                    route_type_display,
                    stream_mode,
                    model,
                    mapping.provider,
                    mapping.actual_model,
                    retry_info
                );

                // Trace the request
                state.message_tracer.trace_request(
                    &trace_id,
                    &anthropic_request,
                    &mapping.provider,
                    &decision.route_type,
                    is_streaming,
                );

                if is_streaming {
                    // Streaming request
                    match provider.send_message_stream(anthropic_request).await {
                        Ok(stream_response) => {
                            // Wrap stream with DLP if enabled for output scanning
                            let stream: Pin<Box<dyn Stream<Item = Result<Bytes, crate::providers::error::ProviderError>> + Send>> =
                                if let Some(ref dlp) = state.dlp_engine {
                                    if dlp.config.scan_output {
                                        Box::pin(crate::features::dlp::stream::DlpStream::new(
                                            stream_response.stream,
                                            Arc::clone(dlp),
                                        ))
                                    } else {
                                        stream_response.stream
                                    }
                                } else {
                                    stream_response.stream
                                };

                            // Convert provider stream to HTTP response
                            let body_stream = stream.map_err(|e| {
                                error!("Stream error: {}", e);
                                std::io::Error::other(e.to_string())
                            });

                            let body = Body::from_stream(body_stream);
                            let mut response_builder = Response::builder()
                                .status(200)
                                .header("Content-Type", "text/event-stream")
                                .header("Cache-Control", "no-cache")
                                .header("Connection", "keep-alive");

                            // Forward Anthropic rate limit headers
                            for (name, value) in stream_response.headers {
                                response_builder = response_builder.header(name, value);
                            }

                            let response = response_builder.body(body).unwrap();

                            return Ok(response);
                        }
                        Err(e) => {
                            state.message_tracer.trace_error(&trace_id, &e.to_string());
                            let is_rate_limit = matches!(
                                &e,
                                crate::providers::error::ProviderError::ApiError {
                                    status: 429,
                                    ..
                                }
                            );
                            if is_rate_limit {
                                warn!("Provider {} rate limited, falling back", mapping.provider);
                                metrics::counter!("grob_ratelimit_hits_total", "provider" => mapping.provider.clone()).increment(1);
                            }
                            metrics::counter!("grob_provider_errors_total", "provider" => mapping.provider.clone()).increment(1);
                            info!(
                                "⚠️ Provider {} streaming failed: {}, trying next fallback",
                                mapping.provider, e
                            );
                            continue;
                        }
                    }
                } else {
                    // Non-streaming request (original behavior)
                    match provider.send_message(anthropic_request).await {
                        Ok(mut response) => {
                            // DLP: sanitize response (deanonymize names, scan secrets)
                            if let Some(ref dlp) = state.dlp_engine {
                                if dlp.config.scan_output {
                                    sanitize_provider_response(&mut response, dlp);
                                }
                            }

                            // Restore original model name in response
                            response.model = original_model;
                            info!(
                                "✅ Request succeeded with provider: {}, response model: {}",
                                mapping.provider, response.model
                            );

                            // Calculate and log metrics with dynamic pricing
                            let latency_ms = start_time.elapsed().as_millis() as u64;
                            let tok_s =
                                (response.usage.output_tokens as f32 * 1000.0) / latency_ms as f32;
                            let cost = calculate_cost(
                                &state,
                                &mapping.actual_model,
                                response.usage.input_tokens,
                                response.usage.output_tokens,
                                is_sub,
                            )
                            .await;
                            info!(
                                "📊 {}@{} {}ms {:.0}t/s {}tok ${:.4}{}",
                                mapping.actual_model,
                                mapping.provider,
                                latency_ms,
                                tok_s,
                                response.usage.output_tokens,
                                cost.estimated_cost_usd,
                                if is_sub { " (subscription)" } else { "" }
                            );

                            // Record Prometheus metrics
                            record_request_metrics(
                                &mapping.actual_model,
                                &mapping.provider,
                                &decision.route_type,
                                "ok",
                                latency_ms,
                                response.usage.input_tokens,
                                response.usage.output_tokens,
                                cost.estimated_cost_usd,
                            );

                            // Record spend for budget tracking
                            record_spend(
                                &state,
                                &mapping.provider,
                                &decision.model_name,
                                cost.estimated_cost_usd,
                            );

                            // Trace the response
                            state
                                .message_tracer
                                .trace_response(&trace_id, &response, latency_ms);

                            return Ok(Json(response).into_response());
                        }
                        Err(e) => {
                            state.message_tracer.trace_error(&trace_id, &e.to_string());
                            let is_rate_limit = matches!(
                                &e,
                                crate::providers::error::ProviderError::ApiError {
                                    status: 429,
                                    ..
                                }
                            );
                            if is_rate_limit {
                                warn!("Provider {} rate limited, falling back", mapping.provider);
                                metrics::counter!("grob_ratelimit_hits_total", "provider" => mapping.provider.clone()).increment(1);
                            }
                            metrics::counter!("grob_provider_errors_total", "provider" => mapping.provider.clone()).increment(1);
                            info!(
                                "⚠️ Provider {} failed: {}, trying next fallback",
                                mapping.provider, e
                            );
                            continue;
                        }
                    }
                }
            } else {
                info!(
                    "⚠️ Provider {} not found in registry, trying next fallback",
                    mapping.provider
                );
                continue;
            }
        }

        error!(
            "❌ All provider mappings failed for model: {}",
            decision.model_name
        );
        Err(AppError::ProviderError(format!(
            "All {} provider mappings failed for model: {}",
            sorted_mappings.len(),
            decision.model_name
        )))
    } else {
        // No model mapping found, try direct provider registry lookup (backward compatibility)
        if let Ok(provider) = inner
            .provider_registry
            .get_provider_for_model(&decision.model_name)
        {
            info!(
                "📦 Using provider from registry (direct lookup): {}",
                decision.model_name
            );

            // Clone the already-parsed request (struct clone, not JSON re-parse)
            let mut anthropic_request = request_for_routing.clone();

            // Save original model name for response
            let original_model = anthropic_request.model.clone();

            // Update model to routed model
            anthropic_request.model = decision.model_name.clone();

            // Call provider
            let mut provider_response = provider
                .send_message(anthropic_request)
                .await
                .map_err(|e| AppError::ProviderError(e.to_string()))?;

            // Restore original model name in response
            provider_response.model = original_model;

            // Return provider response
            return Ok(Json(provider_response).into_response());
        }

        error!(
            "❌ No model mapping or provider found for model: {}",
            decision.model_name
        );
        Err(AppError::ProviderError(format!(
            "No model mapping or provider found for model: {}",
            decision.model_name
        )))
    }
}

/// Handle /v1/messages/count_tokens requests
async fn handle_count_tokens(
    State(state): State<Arc<AppState>>,
    Json(request_json): Json<serde_json::Value>,
) -> Result<Response, AppError> {
    let model = request_json
        .get("model")
        .and_then(|m| m.as_str())
        .unwrap_or("unknown");
    debug!("Received count_tokens request for model: {}", model);

    // Get snapshot of reloadable state
    let inner = state.snapshot();

    // 1. Parse as CountTokensRequest first
    use crate::models::CountTokensRequest;
    let count_request: CountTokensRequest = serde_json::from_value(request_json.clone())
        .map_err(|e| AppError::ParseError(format!("Invalid count_tokens request format: {}", e)))?;

    // 2. Create a minimal AnthropicRequest for routing
    let mut routing_request = AnthropicRequest {
        model: count_request.model.clone(),
        messages: count_request.messages.clone(),
        max_tokens: 1024, // Dummy value for routing
        system: count_request.system.clone(),
        tools: count_request.tools.clone(),
        thinking: None,
        temperature: None,
        top_p: None,
        top_k: None,
        stop_sequences: None,
        stream: None,
        metadata: None,
    };
    let decision = inner
        .router
        .route(&mut routing_request)
        .map_err(|e| AppError::RoutingError(e.to_string()))?;

    debug!(
        "🧮 Routed count_tokens: {} → {} ({})",
        model, decision.model_name, decision.route_type
    );

    // 3. Try model mappings with fallback (1:N mapping)
    if let Some(model_config) = inner.find_model(&decision.model_name) {
        debug!(
            "📋 Found {} provider mappings for token counting: {}",
            model_config.mappings.len(),
            decision.model_name
        );

        // Sort mappings by priority
        let mut sorted_mappings = model_config.mappings.clone();
        sorted_mappings.sort_by_key(|m| m.priority);

        // Try each mapping in priority order
        for (idx, mapping) in sorted_mappings.iter().enumerate() {
            debug!(
                "🔄 Trying token count mapping {}/{}: provider={}, actual_model={}",
                idx + 1,
                sorted_mappings.len(),
                mapping.provider,
                mapping.actual_model
            );

            // Try to get provider from registry
            if let Some(provider) = inner.provider_registry.get_provider(&mapping.provider) {
                // Trust the model mapping configuration - no need to validate

                // Update model to actual model name
                let mut count_request_for_provider = count_request.clone();
                count_request_for_provider.model = mapping.actual_model.clone();

                // Call provider's count_tokens
                match provider.count_tokens(count_request_for_provider).await {
                    Ok(response) => {
                        debug!(
                            "✅ Token count succeeded with provider: {}",
                            mapping.provider
                        );
                        return Ok(Json(response).into_response());
                    }
                    Err(e) => {
                        debug!(
                            "⚠️ Provider {} failed: {}, trying next fallback",
                            mapping.provider, e
                        );
                        continue;
                    }
                }
            } else {
                debug!(
                    "⚠️ Provider {} not found in registry, trying next fallback",
                    mapping.provider
                );
                continue;
            }
        }

        error!(
            "❌ All provider mappings failed for token counting: {}",
            decision.model_name
        );
        Err(AppError::ProviderError(format!(
            "All {} provider mappings failed for token counting: {}",
            sorted_mappings.len(),
            decision.model_name
        )))
    } else {
        // No model mapping found, try direct provider registry lookup (backward compatibility)
        if let Ok(provider) = inner
            .provider_registry
            .get_provider_for_model(&decision.model_name)
        {
            debug!(
                "📦 Using provider from registry (direct lookup) for token counting: {}",
                decision.model_name
            );

            // Update model to routed model
            let mut count_request_for_provider = count_request.clone();
            count_request_for_provider.model = decision.model_name.clone();

            // Call provider's count_tokens
            let response = provider
                .count_tokens(count_request_for_provider)
                .await
                .map_err(|e| AppError::ProviderError(e.to_string()))?;

            debug!("✅ Token count completed via provider");
            return Ok(Json(response).into_response());
        }

        error!(
            "❌ No model mapping or provider found for token counting: {}",
            decision.model_name
        );
        Err(AppError::ProviderError(format!(
            "No model mapping or provider found for token counting: {}",
            decision.model_name
        )))
    }
}

/// Application error types
#[derive(Debug)]
#[allow(clippy::enum_variant_names)]
pub enum AppError {
    RoutingError(String),
    ParseError(String),
    ProviderError(String),
    BudgetExceeded(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_type, message) = match self {
            AppError::RoutingError(msg) => (StatusCode::BAD_REQUEST, "error", msg),
            AppError::ParseError(msg) => (StatusCode::BAD_REQUEST, "invalid_request_error", msg),
            AppError::ProviderError(msg) => (StatusCode::BAD_GATEWAY, "error", msg),
            AppError::BudgetExceeded(msg) => (StatusCode::PAYMENT_REQUIRED, "budget_exceeded", msg),
        };

        let body = Json(serde_json::json!({
            "error": {
                "type": error_type,
                "message": message
            }
        }));

        (status, body).into_response()
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::RoutingError(msg) => write!(f, "Routing error: {}", msg),
            AppError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            AppError::ProviderError(msg) => write!(f, "Provider error: {}", msg),
            AppError::BudgetExceeded(msg) => write!(f, "Budget exceeded: {}", msg),
        }
    }
}

impl std::error::Error for AppError {}

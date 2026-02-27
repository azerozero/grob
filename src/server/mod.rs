pub(crate) mod dispatch;
pub mod fan_out;
mod oauth_handlers;
pub mod openai_compat;

use crate::auth::TokenStore;
use crate::cli::AppConfig;
use crate::features::dlp::session::DlpSessionManager;
use crate::features::dlp::DlpEngine;
use crate::features::token_pricing::spend::SpendTracker;
use crate::features::token_pricing::{SharedPricingTable, TokenCounter};
use crate::message_tracing::MessageTracer;
use crate::models::{AnthropicRequest, RouteType};
use crate::providers::{AuthType, ProviderRegistry};
use crate::router::Router;
use crate::security::{
    apply_security_headers, AuditLog, CircuitBreakerRegistry, RateLimitConfig, RateLimitKey,
    RateLimiter, SecurityHeadersConfig,
};
use crate::storage::GrobStore;
use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, HeaderValue, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router as AxumRouter,
};
use futures::stream::TryStreamExt;
use std::borrow::Cow;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::limit::RequestBodyLimitLayer;
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
    pub spend_tracker: tokio::sync::Mutex<SpendTracker>,
    /// Dynamic pricing table (refreshed from OpenRouter every 24h)
    pub pricing_table: SharedPricingTable,
    /// DLP session manager (None if disabled)
    pub dlp_sessions: Option<Arc<DlpSessionManager>>,
    /// JWT validator (None if auth mode != "jwt")
    pub jwt_validator: Option<Arc<crate::auth::JwtValidator>>,
    /// Webhook tap sender (None if tap is disabled)
    pub tap_sender: Option<Arc<crate::features::tap::TapSender>>,
    /// Rate limiter (None if disabled)
    pub rate_limiter: Option<Arc<RateLimiter>>,
    /// Circuit breaker registry (None if disabled)
    pub circuit_breakers: Option<Arc<CircuitBreakerRegistry>>,
    /// Signed audit log (None if audit_dir not configured)
    pub audit_log: Option<Arc<AuditLog>>,
    /// LLM response cache (None if cache disabled)
    pub response_cache: Option<Arc<crate::cache::ResponseCache>>,
    /// Server start time (for health/upgrade coordination)
    pub started_at: chrono::DateTime<chrono::Utc>,
}

impl AppState {
    /// Get a snapshot of current reloadable state
    pub fn snapshot(&self) -> Arc<ReloadableState> {
        self.inner.read().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

/// Constant-time string comparison to prevent timing side-channel attacks.
fn constant_time_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Builder for constructing AuditEntry with optional EU AI Act fields.
pub struct AuditEntryBuilder {
    tenant_id: String,
    action: crate::security::audit_log::AuditEvent,
    backend: String,
    dlp_rules: Vec<String>,
    ip: String,
    duration_ms: u64,
    model_name: Option<String>,
    input_tokens: Option<u32>,
    output_tokens: Option<u32>,
    risk_level: Option<crate::security::audit_log::RiskLevel>,
}

impl AuditEntryBuilder {
    pub fn new(
        tenant_id: &str,
        action: crate::security::audit_log::AuditEvent,
        backend: &str,
        ip: &str,
        duration_ms: u64,
    ) -> Self {
        Self {
            tenant_id: tenant_id.to_string(),
            action,
            backend: backend.to_string(),
            dlp_rules: vec![],
            ip: ip.to_string(),
            duration_ms,
            model_name: None,
            input_tokens: None,
            output_tokens: None,
            risk_level: None,
        }
    }

    pub fn dlp_rules(mut self, rules: Vec<String>) -> Self {
        self.dlp_rules = rules;
        self
    }

    pub fn model(mut self, model: impl Into<String>) -> Self {
        self.model_name = Some(model.into());
        self
    }

    pub fn tokens(mut self, input: u32, output: u32) -> Self {
        self.input_tokens = Some(input);
        self.output_tokens = Some(output);
        self
    }

    pub fn risk(mut self, level: crate::security::audit_log::RiskLevel) -> Self {
        self.risk_level = Some(level);
        self
    }

    pub fn build(self) -> crate::security::audit_log::AuditEntry {
        use crate::security::audit_log::{AuditEntry, Classification};
        AuditEntry {
            timestamp: chrono::Utc::now(),
            event_id: uuid::Uuid::new_v4().to_string(),
            tenant_id: self.tenant_id,
            user_id: None,
            action: self.action,
            classification: Classification::Nc,
            backend_routed: self.backend,
            request_hash: None,
            dlp_rules_triggered: self.dlp_rules,
            ip_source: self.ip,
            duration_ms: self.duration_ms,
            previous_hash: String::new(), // filled by write()
            signature: vec![],            // filled by write()
            signature_algorithm: String::new(), // filled by write()
            model_name: self.model_name,
            input_tokens: self.input_tokens,
            output_tokens: self.output_tokens,
            risk_level: self.risk_level,
        }
    }
}

/// EU AI Act compliance fields for audit log entries.
struct AuditCompliance<'a> {
    config: &'a crate::cli::ComplianceConfig,
    model_name: Option<&'a str>,
    token_counts: Option<(u32, u32)>,
    risk_level: Option<crate::security::audit_log::RiskLevel>,
}

/// Fire-and-forget audit log entry writer.
/// Builds an `AuditEntry` and writes it; errors are logged but never propagate.
/// When EU AI Act compliance is enabled, conditionally records model name, token counts,
/// and risk level per Articles 12 and 14.
#[allow(clippy::too_many_arguments)]
fn log_audit(
    audit_log: &AuditLog,
    tenant_id: &str,
    action: crate::security::audit_log::AuditEvent,
    backend: &str,
    dlp_rules: Vec<String>,
    ip: &str,
    duration_ms: u64,
    eu: AuditCompliance<'_>,
) {
    let mut builder = AuditEntryBuilder::new(tenant_id, action, backend, ip, duration_ms)
        .dlp_rules(dlp_rules);
    if eu.config.enabled && eu.config.audit_model_name {
        if let Some(m) = eu.model_name {
            builder = builder.model(m);
        }
    }
    if eu.config.enabled && eu.config.audit_token_counts {
        if let Some((i, o)) = eu.token_counts {
            builder = builder.tokens(i, o);
        }
    }
    if eu.config.enabled && eu.config.risk_classification {
        if let Some(r) = eu.risk_level {
            builder = builder.risk(r);
        }
    }
    if let Err(e) = audit_log.write(builder.build()) {
        error!("Audit write failed: {}", e);
    }
}

/// Extract client IP from headers (X-Forwarded-For or fallback to "unknown").
fn extract_client_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Apply EU AI Act transparency headers to a response.
fn apply_transparency_headers(
    headers: &mut HeaderMap,
    provider: &str,
    model: &str,
    audit_id: &str,
) {
    if let Ok(v) = HeaderValue::from_str(provider) {
        headers.insert("x-ai-provider", v);
    }
    if let Ok(v) = HeaderValue::from_str(model) {
        headers.insert("x-ai-model", v);
    }
    if let Ok(v) = HeaderValue::from_str(audit_id) {
        headers.insert("x-grob-audit-id", v);
    }
    headers.insert(
        "x-ai-generated",
        HeaderValue::from_static("true"),
    );
}

/// Auth middleware: supports three modes:
/// - "none" (default): all requests pass
/// - "api_key": checks Bearer token or x-api-key against configured key
/// - "jwt": validates JWT, extracts tenant_id, injects GrobClaims into request extensions
///
/// Skips auth for health/metrics/oauth paths.
async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    // Skip auth for operational/oauth paths
    let path = request.uri().path();
    if matches!(
        path,
        "/health" | "/live" | "/ready" | "/metrics" | "/auth/callback" | "/api/oauth/callback"
    ) {
        return next.run(request).await;
    }

    let inner = state.snapshot();
    let auth_mode = inner.config.auth.mode.as_str();

    // Determine effective auth mode:
    // If [auth] section is not configured (mode == "none"), fall back to legacy server.api_key
    let effective_mode = if auth_mode == "none" {
        let legacy_key = inner.config.server.api_key.as_deref().unwrap_or("");
        if legacy_key.is_empty() {
            "none"
        } else {
            "api_key"
        }
    } else {
        auth_mode
    };

    match effective_mode {
        "none" => next.run(request).await,
        "api_key" => {
            // Use [auth].api_key or fall back to server.api_key
            let api_key = inner
                .config
                .auth
                .api_key
                .as_deref()
                .filter(|k| !k.is_empty())
                .or_else(|| inner.config.server.api_key.as_deref())
                .unwrap_or("");

            if api_key.is_empty() {
                return next.run(request).await;
            }

            let token = extract_bearer_or_api_key(&request);
            match token {
                Some(t) if constant_time_eq(t, api_key) => next.run(request).await,
                _ => auth_error_response("Invalid or missing API key. Provide via Authorization: Bearer <key> or x-api-key header."),
            }
        }
        "jwt" => {
            let validator = match &state.jwt_validator {
                Some(v) => v,
                None => {
                    error!("JWT auth mode configured but no validator initialized");
                    return auth_error_response(
                        "Server misconfiguration: JWT validator not initialized",
                    );
                }
            };

            let token = request
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "));

            match token {
                Some(t) => match validator.validate(t) {
                    Ok(claims) => {
                        debug!("JWT auth: tenant_id={}", claims.tenant_id());
                        request.extensions_mut().insert(claims);
                        next.run(request).await
                    }
                    Err(e) => auth_error_response(&format!("JWT validation failed: {}", e)),
                },
                None => auth_error_response(
                    &crate::auth::jwt::AuthError::MissingToken.to_string(),
                ),
            }
        }
        other => {
            error!("Unknown auth mode: {}", other);
            auth_error_response(&format!("Unknown auth mode: {}", other))
        }
    }
}

/// Request ID middleware: reads X-Request-Id header or generates UUID v4.
/// Stores in request extensions and echoes in response header.
async fn request_id_middleware(mut request: Request<Body>, next: Next) -> Response {
    let request_id = request
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    request
        .extensions_mut()
        .insert(RequestId(request_id.clone()));

    let mut response = next.run(request).await;
    if let Ok(val) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-request-id", val);
    }
    response
}

/// Stored in request extensions for correlation
#[derive(Clone, Debug)]
struct RequestId(String);

/// Rate limiting middleware: checks rate limiter before processing.
/// Returns 429 with Retry-After header when rate exceeded.
async fn rate_limit_check_middleware(
    State(state): State<Arc<AppState>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    // Skip rate limiting for health/metrics/liveness/readiness paths
    let path = request.uri().path();
    if matches!(path, "/health" | "/metrics" | "/live" | "/ready") {
        return next.run(request).await;
    }

    let limiter = match &state.rate_limiter {
        Some(l) => l,
        None => return next.run(request).await,
    };

    // Extract key: JWT tenant_id > Bearer token > x-api-key > IP (fallback "anonymous")
    let key = request
        .extensions()
        .get::<crate::auth::GrobClaims>()
        .map(|c| RateLimitKey::Tenant(c.tenant_id().to_string()))
        .or_else(|| {
            request
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
                .map(|k| RateLimitKey::Tenant(k.to_string()))
        })
        .or_else(|| {
            request
                .headers()
                .get("x-api-key")
                .and_then(|v| v.to_str().ok())
                .map(|k| RateLimitKey::Tenant(k.to_string()))
        })
        .unwrap_or_else(|| RateLimitKey::Ip("anonymous".to_string()));

    let (allowed, _remaining, reset_after) = limiter.check(&key).await;

    if !allowed {
        metrics::counter!("grob_ratelimit_rejected_total").increment(1);
        let retry_after = reset_after
            .map(|d| d.as_secs().max(1).to_string())
            .unwrap_or_else(|| "1".to_string());
        return Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .header("Retry-After", &retry_after)
            .header("X-RateLimit-Remaining", "0")
            .header("Content-Type", "application/json")
            .body(Body::from(
                r#"{"error":{"type":"rate_limit_error","message":"Rate limit exceeded. Please slow down."}}"#,
            ))
            .expect("rate limit response");
    }

    next.run(request).await
}

/// Security headers middleware: applies OWASP security headers to all responses.
async fn security_headers_response_middleware(request: Request<Body>, next: Next) -> Response {
    let response = next.run(request).await;
    let config = SecurityHeadersConfig::api_mode();
    apply_security_headers(response, &config)
}

/// Extract Bearer token or x-api-key from request headers.
fn extract_bearer_or_api_key(request: &Request<Body>) -> Option<&str> {
    request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .or_else(|| {
            request
                .headers()
                .get("x-api-key")
                .and_then(|v| v.to_str().ok())
        })
}

fn auth_error_response(message: &str) -> Response {
    let body = Json(serde_json::json!({
        "error": {
            "type": "authentication_error",
            "message": message
        }
    }));
    (StatusCode::UNAUTHORIZED, body).into_response()
}

/// Start the HTTP server with graceful shutdown support.
/// When the `shutdown_signal` future completes, the server stops accepting new
/// connections and drains in-flight requests (up to 30 s).
pub async fn start_server(
    config: AppConfig,
    config_source: crate::cli::ConfigSource,
    shutdown_signal: impl std::future::Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let router = Router::new(config.clone());

    // Initialize shared storage (redb)
    let grob_store = Arc::new(
        GrobStore::open(&GrobStore::default_path())
            .map_err(|e| anyhow::anyhow!("Failed to initialize storage: {}", e))?,
    );
    info!("💾 Storage initialized at {}", grob_store.path().display());

    // Initialize OAuth token store backed by GrobStore
    #[cfg(feature = "oauth")]
    let token_store = {
        let ts = TokenStore::with_store(grob_store.clone())
            .map_err(|e| anyhow::anyhow!("Failed to initialize token store: {}", e))?;
        let existing_tokens = ts.list_providers();
        if !existing_tokens.is_empty() {
            info!(
                "🔐 Loaded {} OAuth tokens from storage",
                existing_tokens.len()
            );
        }
        ts
    };
    #[cfg(not(feature = "oauth"))]
    let token_store = TokenStore::new_empty();

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

    // Initialize spend tracker backed by GrobStore
    let spend_tracker = SpendTracker::with_store(grob_store.clone());
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

    // Initialize DLP session manager (if DLP enabled in config)
    #[cfg(feature = "dlp")]
    let dlp_sessions = {
        let sessions = DlpSessionManager::from_config(config.dlp.clone());
        // Spawn DLP signed config hot-reload (if enabled)
        if let Some(ref dlp_mgr) = sessions {
            let dlp_cfg = dlp_mgr.config();
            if dlp_cfg.signed_config.enabled {
                let public_key = if dlp_cfg.signed_config.verify_signature {
                    match crate::features::dlp::signed_config::load_public_key(
                        &dlp_cfg.signed_config.public_key_path,
                    ) {
                        Ok(pk) => Some(pk),
                        Err(e) => {
                            warn!("Failed to load DLP signing public key: {}", e);
                            None
                        }
                    }
                } else {
                    None
                };
                crate::features::dlp::signed_config::spawn_hot_reload(
                    dlp_cfg.signed_config.clone(),
                    dlp_mgr.hot_config().clone(),
                    dlp_cfg.url_exfil.domain_match_mode.clone(),
                    public_key,
                );
            }
        }
        sessions
    };
    #[cfg(not(feature = "dlp"))]
    let dlp_sessions: Option<Arc<DlpSessionManager>> = None;

    // Initialize JWT validator (if auth mode == "jwt")
    let jwt_validator = if config.auth.mode == "jwt" {
        let validator = Arc::new(
            crate::auth::JwtValidator::from_config(&config.auth.jwt)
                .map_err(|e| anyhow::anyhow!("Failed to initialize JWT validator: {}", e))?,
        );
        // Initial JWKS fetch if configured
        if validator.jwks_url().is_some() {
            let v = validator.clone();
            if let Err(e) = v.refresh_jwks().await {
                warn!("Initial JWKS fetch failed (will retry): {}", e);
            }
            // Spawn background JWKS refresh with exponential backoff on failure
            let base_interval = config.auth.jwt.jwks_refresh_interval;
            tokio::spawn(async move {
                let mut current_interval = base_interval;
                let max_interval = base_interval * 8;
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(current_interval)).await;
                    match v.refresh_jwks().await {
                        Ok(_) => {
                            current_interval = base_interval; // Reset on success
                        }
                        Err(e) => {
                            warn!(
                                "JWKS refresh failed (next retry in {}s): {}",
                                current_interval.min(max_interval) * 2,
                                e
                            );
                            current_interval = (current_interval * 2).min(max_interval);
                        }
                    }
                }
            });
        }
        info!("🔐 JWT auth enabled");
        Some(validator)
    } else {
        None
    };

    // Initialize webhook tap (if enabled in config)
    #[cfg(feature = "tap")]
    let tap_sender = crate::features::tap::init_tap(&config.tap);
    #[cfg(not(feature = "tap"))]
    let tap_sender: Option<Arc<crate::features::tap::TapSender>> = None;

    // Build reloadable state
    let reloadable = Arc::new(ReloadableState::new(
        config.clone(),
        router,
        provider_registry,
    ));

    // Initialize security layer from config
    let security_enabled = config.security.enabled;
    let rate_limiter = if security_enabled {
        let rl_config = RateLimitConfig {
            requests_per_second: config.security.rate_limit_rps,
            burst: config.security.rate_limit_burst,
            _window: std::time::Duration::from_secs(60),
        };
        info!(
            "🛡️  Security: rate limit {}rps burst={}, body limit {}MB, headers={}, circuit_breaker={}",
            config.security.rate_limit_rps,
            config.security.rate_limit_burst,
            config.security.max_body_size / (1024 * 1024),
            config.security.security_headers,
            config.security.circuit_breaker,
        );
        Some(Arc::new(RateLimiter::new(rl_config)))
    } else {
        info!("🛡️  Security middleware disabled");
        None
    };

    let circuit_breakers = if security_enabled && config.security.circuit_breaker {
        Some(Arc::new(CircuitBreakerRegistry::new()))
    } else {
        None
    };

    // Initialize audit log (if audit_dir configured)
    #[cfg(not(feature = "compliance"))]
    let audit_log: Option<Arc<AuditLog>> = None;
    #[cfg(feature = "compliance")]
    let audit_log = if !config.security.audit_dir.is_empty() {
        let audit_dir = if config.security.audit_dir.starts_with('~') {
            let home = dirs::home_dir().unwrap_or_default();
            home.join(&config.security.audit_dir[2..])
        } else {
            std::path::PathBuf::from(&config.security.audit_dir)
        };
        let signing_algorithm = if config.security.audit_signing_algorithm.is_empty() {
            crate::security::audit_log::SigningAlgorithm::default()
        } else {
            crate::security::audit_log::SigningAlgorithm::from_str_config(
                &config.security.audit_signing_algorithm,
            )
        };
        let hmac_key_path = if config.security.audit_hmac_key_path.is_empty() {
            None
        } else {
            Some(std::path::PathBuf::from(
                &config.security.audit_hmac_key_path,
            ))
        };
        match AuditLog::new(crate::security::audit_log::AuditConfig {
            log_dir: audit_dir.clone(),
            sign_key_path: Some(audit_dir.join("audit_key.pem")),
            signing_algorithm,
            hmac_key_path,
        }) {
            Ok(log) => {
                info!("📝 Audit logging enabled: {}", audit_dir.display());
                Some(Arc::new(log))
            }
            Err(e) => {
                error!("⚠️  Failed to initialize audit log: {}", e);
                None
            }
        }
    } else {
        None
    };

    // Initialize response cache (if enabled)
    let response_cache = if config.cache.enabled {
        let cache = crate::cache::ResponseCache::new(
            config.cache.max_capacity,
            config.cache.ttl_secs,
            config.cache.max_entry_bytes,
        );
        info!(
            "💾 Response cache enabled: max_capacity={}, ttl={}s, max_entry={}B",
            config.cache.max_capacity, config.cache.ttl_secs, config.cache.max_entry_bytes
        );
        Some(Arc::new(cache))
    } else {
        None
    };

    let state = Arc::new(AppState {
        inner: std::sync::RwLock::new(reloadable),
        token_store,
        config_source,
        message_tracer,
        metrics_handle,
        active_requests: std::sync::atomic::AtomicU64::new(0),
        spend_tracker: tokio::sync::Mutex::new(spend_tracker),
        pricing_table,
        dlp_sessions,
        jwt_validator,
        tap_sender,
        rate_limiter,
        circuit_breakers,
        audit_log,
        response_cache,
        started_at: chrono::Utc::now(),
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
        .route("/live", get(liveness_check))
        .route("/ready", get(readiness_check))
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

    // Middleware stack (applied bottom-to-top, so outermost layer listed last):
    // 1. Auth middleware (innermost — runs after rate limit + request ID)
    let app = app.layer(axum::middleware::from_fn_with_state(
        state.clone(),
        auth_middleware,
    ));

    // 2. Rate limiting middleware (before auth — outermost check)
    if security_enabled {
        // We apply rate limiting via from_fn_with_state on the already-built app
    }
    let app = app.layer(axum::middleware::from_fn_with_state(
        state.clone(),
        rate_limit_check_middleware,
    ));

    // 3. Security headers middleware (wraps response)
    let app = if config.security.security_headers {
        app.layer(axum::middleware::from_fn(
            security_headers_response_middleware,
        ))
    } else {
        app
    };

    // 4. Request body size limit
    let app = app.layer(RequestBodyLimitLayer::new(config.security.max_body_size));

    // 5. Request ID middleware (outermost — always runs first)
    let app = app.layer(axum::middleware::from_fn(request_id_middleware));

    // Clone state before moving it
    let oauth_state = state.clone();
    let drain_state = state.clone();
    let app = app.with_state(state);

    // Bind to main address (IPv6 addresses need bracket notation)
    let addr = crate::cli::format_bind_addr(&config.server.host, config.server.port);

    // TLS support (requires `tls` cargo feature)
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

    // Start OAuth callback (must be before main server await)
    spawn_oauth_callback(oauth_state);

    if !tls_enabled {
        // Use SO_REUSEPORT for zero-downtime restart support
        let listener = crate::net::bind_reuseport(&addr).await?;
        info!("🚀 Server listening on {} (SO_REUSEPORT)", addr);

        // Start main server (plain HTTP) with graceful shutdown
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal)
            .await?;
    } else if tls_acme {
        // ACME auto-certificate mode
        #[cfg(feature = "acme")]
        {
            let acceptor = crate::acme::build_acme_acceptor(&config.server.tls.acme)?;

            info!("🔒 Server listening on {} (ACME TLS, SO_REUSEPORT)", addr);

            let listener = crate::net::bind_reuseport(&addr).await?;
            axum_server::Server::bind(addr.parse()?)
                .acceptor(acceptor)
                .serve(app.into_make_service())
                .await?;
            // Keep listener alive for SO_REUSEPORT
            drop(listener);
        }
    } else {
        // Manual TLS certificate mode
        #[cfg(feature = "tls")]
        {
            use axum_server::tls_rustls::RustlsConfig;
            let rustls_config = RustlsConfig::from_pem_file(
                &config.server.tls.cert_path,
                &config.server.tls.key_path,
            )
            .await?;

            info!("🔒 Server listening on {} (TLS, SO_REUSEPORT)", addr);

            // Use SO_REUSEPORT std listener for zero-downtime restart support
            let std_listener = crate::net::bind_reuseport_std(&addr)?;
            axum_server::from_tcp_rustls(std_listener, rustls_config)
                .serve(app.into_make_service())
                .await?;
        }
    }

    // Drain in-flight requests (max 30s)
    let drain_start = std::time::Instant::now();
    let drain_timeout = std::time::Duration::from_secs(30);
    loop {
        let active = drain_state
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

    Ok(())
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

/// Health check endpoint
async fn health_check(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let active = state
        .active_requests
        .load(std::sync::atomic::Ordering::Relaxed);
    let spend_total = {
        let tracker = state.spend_tracker.lock().await;
        tracker.total()
    };
    let inner = state.snapshot();
    let budget_limit = inner.config.budget.monthly_limit_usd;
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
    if let Some(ref cb) = state.circuit_breakers {
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
    let tracker = state.spend_tracker.lock().await;
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
        .expect("metrics response builder")
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
    *state.inner.write().unwrap_or_else(|e| e.into_inner()) = new_inner.clone();

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
    )
    .increment(1);
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
async fn check_budget(
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

    let tracker = state.spend_tracker.lock().await;

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

/// Record spend after a successful request (global + per-tenant if applicable)
async fn record_spend(
    state: &Arc<AppState>,
    provider_name: &str,
    model_name: &str,
    cost: f64,
    tenant_id: Option<&str>,
) {
    if cost > 0.0 {
        let mut tracker = state.spend_tracker.lock().await;
        if let Some(tenant) = tenant_id {
            tracker.record_tenant(tenant, provider_name, model_name, cost);
        } else {
            tracker.record(provider_name, model_name, cost);
        }
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

/// Maximum retries per provider before falling back to the next mapping.
const MAX_RETRIES: u32 = 2;

/// Check if a provider error is retryable (429, 500, 502, 503, network errors).
fn is_retryable(e: &crate::providers::error::ProviderError) -> bool {
    match e {
        crate::providers::error::ProviderError::ApiError { status, .. } => {
            matches!(status, 429 | 500 | 502 | 503)
        }
        crate::providers::error::ProviderError::HttpError(_) => true,
        _ => false,
    }
}

/// Calculate retry delay with exponential backoff and jitter.
fn retry_delay(attempt: u32) -> std::time::Duration {
    let base_ms = 200u64 * 4u64.pow(attempt);
    let jitter = rand::random::<u64>() % (base_ms / 2 + 1);
    std::time::Duration::from_millis(base_ms + jitter)
}

/// Handle /v1/chat/completions requests (OpenAI-compatible endpoint)
/// Supports both streaming (SSE) and non-streaming responses, plus tool calling.
async fn handle_openai_chat_completions(
    State(state): State<Arc<AppState>>,
    claims: Option<axum::Extension<crate::auth::GrobClaims>>,
    axum::Extension(request_id): axum::Extension<RequestId>,
    headers: HeaderMap,
    Json(openai_request): Json<openai_compat::OpenAIRequest>,
) -> Result<Response, AppError> {
    let _guard = ActiveRequestGuard::new(&state);
    let model = openai_request.model.clone();
    let is_streaming = openai_request.stream == Some(true);
    let tenant_id = claims.as_ref().map(|c| c.tenant_id().to_string());
    let peer_ip = extract_client_ip(&headers);

    let inner = state.snapshot();
    let session_key = tenant_id.as_deref().or_else(|| extract_api_key(&headers));
    let dlp = state.dlp_sessions.as_ref().map(|mgr| mgr.engine_for(session_key));

    // Transform OpenAI → Anthropic format
    let mut anthropic_request = openai_compat::transform_openai_to_anthropic(openai_request)
        .map_err(|e| AppError::ParseError(format!("Failed to transform OpenAI request: {}", e)))?;

    let ctx = dispatch::DispatchContext {
        state: &state,
        inner: &inner,
        dlp: &dlp,
        model: model.clone(),
        is_streaming,
        tenant_id,
        peer_ip,
        req_id: &request_id.0,
        start_time: std::time::Instant::now(),
        headers: &headers,
        trace_id: None,
    };

    match dispatch::dispatch(&ctx, &mut anthropic_request).await? {
        dispatch::DispatchResult::CacheHit(resp) => Ok(resp),

        dispatch::DispatchResult::Streaming { stream, provider, actual_model, .. } => {
            let mut transformer = openai_compat::AnthropicToOpenAIStream::new(model.clone());
            let mapped = stream
                .map_ok(move |bytes| transformer.transform_bytes(&bytes))
                .try_filter(|b| futures::future::ready(!b.is_empty()));
            let body = Body::from_stream(mapped.map_err(|e| std::io::Error::other(e.to_string())));
            let mut response = Response::builder()
                .status(200)
                .header("Content-Type", "text/event-stream")
                .header("Cache-Control", "no-cache")
                .header("Connection", "keep-alive")
                .body(body)
                .expect("streaming response builder");
            if inner.config.compliance.enabled && inner.config.compliance.transparency_headers {
                apply_transparency_headers(response.headers_mut(), &provider, &actual_model, &request_id.0);
            }
            Ok(response)
        }

        dispatch::DispatchResult::Complete { response: anthropic_response, provider, actual_model, .. } => {
            let openai_response = openai_compat::transform_anthropic_to_openai(anthropic_response, model.clone());
            if inner.config.compliance.enabled && inner.config.compliance.transparency_headers {
                let body = serde_json::to_vec(&openai_response).unwrap_or_default();
                let mut resp = Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .expect("response builder");
                apply_transparency_headers(resp.headers_mut(), &provider, &actual_model, &request_id.0);
                Ok(resp)
            } else {
                Ok(Json(openai_response).into_response())
            }
        }

        dispatch::DispatchResult::FanOut { response } => {
            let openai_response = openai_compat::transform_anthropic_to_openai(response, model.clone());
            Ok(Json(openai_response).into_response())
        }
    }
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

        // GDPR/region filtering: if gdpr=true or region is set, only keep matching providers
        let gdpr = inner.config.router.gdpr;
        let required_region = inner.config.router.region.as_deref();
        if gdpr || required_region.is_some() {
            let region_filter = required_region.unwrap_or("eu");
            sorted.retain(|m| {
                let provider_region = inner
                    .config
                    .providers
                    .iter()
                    .find(|p| p.name == m.provider)
                    .and_then(|p| p.region.as_deref())
                    .unwrap_or("global");
                provider_region == region_filter || provider_region == "global"
            });
            if sorted.is_empty() {
                return Err(AppError::RoutingError(format!(
                    "No providers match region '{}' for model '{}' (GDPR filtering enabled)",
                    region_filter, decision.model_name
                )));
            }
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

/// Extract API key from request headers (Bearer token or x-api-key).
fn extract_api_key(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .or_else(|| headers.get("x-api-key").and_then(|v| v.to_str().ok()))
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
                "owned_by": "grob",
                "capabilities": {
                    "tool_calling": true,
                    "streaming": true
                }
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
    claims: Option<axum::Extension<crate::auth::GrobClaims>>,
    axum::Extension(request_id): axum::Extension<RequestId>,
    headers: HeaderMap,
    Json(request_json): Json<serde_json::Value>,
) -> Result<Response, AppError> {
    let _guard = ActiveRequestGuard::new(&state);
    let req_id = &request_id.0;
    let model: String = request_json
        .get("model")
        .and_then(|m| m.as_str())
        .unwrap_or("unknown")
        .to_string();
    let tenant_id = claims.as_ref().map(|c| c.tenant_id().to_string());
    let peer_ip = extract_client_ip(&headers);
    let inner = state.snapshot();
    let session_key = tenant_id.as_deref().or_else(|| extract_api_key(&headers));
    let dlp = state.dlp_sessions.as_ref().map(|mgr| mgr.engine_for(session_key));
    let trace_id = state.message_tracer.new_trace_id();

    // DEBUG: Log request body for debugging (gate serialization on log level)
    if tracing::event_enabled!(tracing::Level::DEBUG) {
        if let Ok(json_str) = serde_json::to_string_pretty(&request_json) {
            tracing::debug!("📥 Incoming request body:\n{}", json_str);
        }
    }

    let mut request: AnthropicRequest = serde_json::from_value(request_json)
        .map_err(|e| {
            tracing::error!("❌ Failed to parse request: {}", e);
            AppError::ParseError(format!("Invalid request format: {}", e))
        })?;

    let is_streaming = request.stream == Some(true);

    let ctx = dispatch::DispatchContext {
        state: &state,
        inner: &inner,
        dlp: &dlp,
        model: model.clone(),
        is_streaming,
        tenant_id,
        peer_ip,
        req_id,
        start_time: std::time::Instant::now(),
        headers: &headers,
        trace_id: Some(trace_id),
    };

    match dispatch::dispatch(&ctx, &mut request).await? {
        dispatch::DispatchResult::CacheHit(resp) => Ok(resp),

        dispatch::DispatchResult::Streaming { stream, provider, actual_model, upstream_headers } => {
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

            // Forward upstream rate-limit headers
            for (name, value) in &upstream_headers {
                response_builder = response_builder.header(name.as_str(), value.as_str());
            }

            // Transparency headers
            if inner.config.compliance.enabled && inner.config.compliance.transparency_headers {
                let mut hdrs = HeaderMap::new();
                apply_transparency_headers(&mut hdrs, &provider, &actual_model, req_id);
                for (k, v) in hdrs {
                    if let Some(k) = k {
                        response_builder = response_builder.header(k, v);
                    }
                }
            }

            let response = response_builder
                .body(body)
                .expect("streaming response builder");
            Ok(response)
        }

        dispatch::DispatchResult::Complete { response, provider, actual_model, response_bytes } => {
            if inner.config.compliance.enabled && inner.config.compliance.transparency_headers {
                let body = response_bytes.unwrap_or_else(|| serde_json::to_vec(&response).unwrap_or_default());
                let mut resp = Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .expect("response builder");
                apply_transparency_headers(resp.headers_mut(), &provider, &actual_model, req_id);
                Ok(resp)
            } else if let Some(body) = response_bytes {
                Ok(Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .expect("response builder"))
            } else {
                Ok(Json(response).into_response())
            }
        }

        dispatch::DispatchResult::FanOut { response } => {
            Ok(Json(response).into_response())
        }
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
        tool_choice: None,
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
    DlpBlocked(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_type, message) = match self {
            AppError::RoutingError(msg) => (StatusCode::BAD_REQUEST, "error", msg),
            AppError::ParseError(msg) => (StatusCode::BAD_REQUEST, "invalid_request_error", msg),
            AppError::ProviderError(msg) => (StatusCode::BAD_GATEWAY, "error", msg),
            AppError::BudgetExceeded(msg) => (StatusCode::PAYMENT_REQUIRED, "budget_exceeded", msg),
            AppError::DlpBlocked(msg) => (StatusCode::BAD_REQUEST, "dlp_block", msg),
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
            AppError::DlpBlocked(msg) => write!(f, "DLP blocked: {}", msg),
        }
    }
}

impl std::error::Error for AppError {}

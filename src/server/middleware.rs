use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, HeaderValue, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;
use tracing::{debug, error};

use crate::security::{apply_security_headers, RateLimitKey, SecurityHeadersConfig};

use super::AppState;

/// Constant-time string comparison to prevent timing side-channel attacks.
///
/// NOTE: the early length check leaks the *length* of `a`/`b` via timing (an
/// observable early return on mismatch). For secrets whose length is itself
/// sensitive, prefer [`constant_time_eq_hashed`], which hides it.
pub(crate) fn constant_time_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Constant-time, length-hiding string comparison.
///
/// Hashes both inputs to fixed-size 32-byte SHA-256 digests, then compares the
/// digests in constant time. Because the digests are always 32 bytes, the
/// comparison never short-circuits on a length mismatch — so, unlike
/// [`constant_time_eq`], it leaks neither the value nor the *length* of either
/// input via timing. Reuses the `sha2` crate already in the dependency tree
/// (JWT/PKCE/AES); no new dependency. Use it for high-value bearer tokens such
/// as the `/metrics` token.
pub(crate) fn constant_time_eq_hashed(a: &str, b: &str) -> bool {
    use sha2::{Digest, Sha256};
    use subtle::ConstantTimeEq;
    let a_digest = Sha256::digest(a.as_bytes());
    let b_digest = Sha256::digest(b.as_bytes());
    a_digest.as_slice().ct_eq(b_digest.as_slice()).into()
}

/// Extract client IP from headers (X-Forwarded-For or fallback to "unknown").
pub(crate) fn extract_client_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Apply EU AI Act transparency headers to a response.
pub(crate) fn apply_transparency_headers(
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
    headers.insert("x-ai-generated", HeaderValue::from_static("true"));
}

/// Returns true when EU AI Act transparency headers should be added.
pub(crate) fn should_apply_transparency(config: &crate::config::AppConfig) -> bool {
    config.compliance.enabled && config.compliance.transparency_headers
}

/// Extract API credential from request headers (Bearer token or x-api-key).
pub(crate) fn extract_api_credential(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .or_else(|| headers.get("x-api-key").and_then(|v| v.to_str().ok()))
}

/// Builds a 401 JSON error response with the given message.
pub(crate) fn auth_error_response(message: &str) -> Response {
    let body = Json(serde_json::json!({
        "error": {
            "type": "authentication_error",
            "message": message
        }
    }));
    (StatusCode::UNAUTHORIZED, body).into_response()
}

/// Stored in request extensions for correlation
#[derive(Clone, Debug)]
pub struct RequestId(pub String);

/// Auth middleware: supports three modes:
/// - "none" (default): all requests pass
/// - "api_key": checks Bearer token or x-api-key against configured key
/// - "jwt": validates JWT, extracts tenant_id, injects GrobClaims into request extensions
///
/// Skips auth for health/metrics/oauth paths.
pub(crate) async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let path = request.uri().path();
    if matches!(
        path,
        "/health" | "/live" | "/ready" | "/metrics" | "/auth/callback" | "/api/oauth/callback"
    ) {
        return next.run(request).await;
    }

    let inner = state.snapshot();
    let auth_mode = inner.config.auth.mode.as_str();

    let effective_mode = if auth_mode == "none" {
        // SAFETY: expose_secret() used only for emptiness check, value is never logged.
        let legacy_key = inner
            .config
            .server
            .api_key
            .as_ref()
            .map(|s| secrecy::ExposeSecret::expose_secret(s).as_str())
            .unwrap_or("");
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
            // SAFETY: expose_secret() used only for constant-time comparison,
            // value is never logged or included in any tracing output.
            let api_key = inner
                .config
                .auth
                .api_key
                .as_ref()
                .map(|s| secrecy::ExposeSecret::expose_secret(s).as_str())
                .filter(|k| !k.is_empty())
                .or_else(|| {
                    inner
                        .config
                        .server
                        .api_key
                        .as_ref()
                        .map(|s| secrecy::ExposeSecret::expose_secret(s).as_str())
                })
                .unwrap_or("");

            if api_key.is_empty() {
                return next.run(request).await;
            }

            let token = extract_api_credential(request.headers());
            match token {
                Some(t) if constant_time_eq(t, api_key) => next.run(request).await,
                Some(t) => {
                    // Static key didn't match — try virtual key lookup.
                    match resolve_virtual_key(&state, t) {
                        Some(vk_ctx) => {
                            debug!("Virtual key auth: tenant={}, key={}", vk_ctx.tenant_id, vk_ctx.name);
                            request.extensions_mut().insert(vk_ctx);
                            next.run(request).await
                        }
                        None => auth_error_response("Invalid or missing API key. Provide via Authorization: Bearer <key> or x-api-key header."),
                    }
                }
                None => auth_error_response("Invalid or missing API key. Provide via Authorization: Bearer <key> or x-api-key header."),
            }
        }
        "jwt" => {
            let Some(validator) = &state.security.jwt_validator else {
                error!("JWT auth mode configured but no validator initialized");
                return auth_error_response(
                    "Server misconfiguration: JWT validator not initialized",
                );
            };

            let Some(token) = request
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
            else {
                return auth_error_response(&crate::auth::jwt::AuthError::MissingToken.to_string());
            };

            match validator.validate(token) {
                Ok(claims) => {
                    debug!("JWT auth: tenant_id={}", claims.tenant_id());
                    request.extensions_mut().insert(claims);
                    next.run(request).await
                }
                Err(e) => auth_error_response(&format!("JWT validation failed: {}", e)),
            }
        }
        other => {
            error!("Unknown auth mode: {}", other);
            auth_error_response(&format!("Unknown auth mode: {}", other))
        }
    }
}

/// Resolves a bearer token as a virtual API key.
///
/// Hashes the token with SHA-256, looks up the record in storage,
/// and returns a [`VirtualKeyContext`] if the key is valid (not revoked, not expired).
fn resolve_virtual_key(
    state: &Arc<AppState>,
    token: &str,
) -> Option<crate::auth::virtual_keys::VirtualKeyContext> {
    use sha2::{Digest, Sha256};

    // Only attempt lookup for tokens with the grob_ prefix.
    if !token.starts_with("grob_") {
        return None;
    }

    let hash = hex::encode(Sha256::digest(token.as_bytes()));
    let record = state.grob_store.lookup_virtual_key(&hash)?;

    if record.revoked {
        debug!("Virtual key {} is revoked", record.prefix);
        return None;
    }

    if let Some(expires_at) = record.expires_at {
        if chrono::Utc::now() >= expires_at {
            debug!("Virtual key {} is expired", record.prefix);
            return None;
        }
    }

    Some(crate::auth::virtual_keys::VirtualKeyContext {
        key_id: record.id,
        tenant_id: record.tenant_id,
        name: record.name,
        budget_usd: record.budget_usd,
        rate_limit_rps: record.rate_limit_rps,
        allowed_models: record.allowed_models,
        allowed_providers: record.allowed_providers,
    })
}

/// Request ID middleware: reads X-Request-Id header or generates UUID v4.
/// Stores in request extensions and echoes in response header.
pub(crate) async fn request_id_middleware(mut request: Request<Body>, next: Next) -> Response {
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

/// Quota advertised to clients, in requests.
///
/// The bucket's capacity (`burst`), not the refill rate. `remaining` is a count
/// of tokens held, which is bounded by the capacity, so advertising the rate
/// instead would let `remaining` exceed the limit — a client seeing
/// `limit=10, remaining=19` cannot pace itself against either number.
fn advertised_quota(config: &crate::security::RateLimitConfig) -> u32 {
    config.burst.max(config.requests_per_second)
}

/// Window advertised for a quota, in whole seconds.
///
/// A token bucket has no fixed window: it refills continuously. The closest
/// honest equivalent is how long a full burst takes to accrue, which is what a
/// client needs in order to pace itself. Rounded up and floored at 1, because
/// the IETF field is a non-zero integer number of seconds.
fn window_seconds(config: &crate::security::RateLimitConfig) -> u64 {
    let rps = u64::from(config.requests_per_second.max(1));
    let burst = u64::from(config.burst.max(1));
    burst.div_ceil(rps).max(1)
}

/// Writes the quota fields onto a response.
///
/// Emits both the IETF `RateLimit` / `RateLimit-Policy` fields
/// (draft-ietf-httpapi-ratelimit-headers) and the de-facto `X-RateLimit-*`
/// headers. The draft is not yet an RFC and no client library speaks it
/// exclusively, so sending only the standard fields would be correct and
/// useless; sending only `X-` would ignore where the ecosystem is going. Both
/// carry identical numbers.
///
/// Silently skips a field whose value will not parse as a header, so a
/// malformed quota can never turn a served response into a failure: these
/// fields are advisory, and the request has already been decided.
fn apply_ratelimit_headers(headers: &mut HeaderMap, limit: u32, remaining: u32, window_secs: u64) {
    // A limit of 0 means "no quota configured"; advertising it would tell the
    // client it may never send anything.
    if limit == 0 {
        return;
    }

    let set = |headers: &mut HeaderMap, name: &'static str, value: String| {
        if let Ok(v) = HeaderValue::from_str(&value) {
            headers.insert(name, v);
        }
    };

    // IETF structured fields: the policy is stable, the service limit is not.
    set(
        headers,
        "ratelimit-policy",
        format!(r#""default";q={limit};w={window_secs}"#),
    );
    set(
        headers,
        "ratelimit",
        format!(r#""default";r={remaining};t={window_secs}"#),
    );

    // De-facto headers, for every client that already parses them.
    set(headers, "x-ratelimit-limit", limit.to_string());
    set(headers, "x-ratelimit-remaining", remaining.to_string());
    set(headers, "x-ratelimit-reset", window_secs.to_string());
}

/// Hex-encoded SHA-256 of a credential, for use as an opaque bucket key.
///
/// Same input yields the same bucket, so throttling is unaffected; what changes
/// is that the secret itself is never held in the bucket map.
fn hash_credential(credential: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(credential.as_bytes()))
}

/// Returns the per-client rate-limit key for `claims`, when enabled and available.
///
/// `None` means "not client-scoped": either the feature is off or the token
/// carries no `azp`/`client_id`. The caller then keeps the tenant key rather
/// than inventing one, so a self-signed token or an API key is never merged
/// into a client bucket it does not belong to.
fn client_rate_limit_key(
    state: &AppState,
    claims: &crate::auth::GrobClaims,
) -> Option<RateLimitKey> {
    let inner = state.snapshot();
    if !inner.config.security.rate_limit_by_client {
        return None;
    }
    claims
        .client_id()
        .map(|id| RateLimitKey::Client(id.to_string()))
}

/// Returns the rate-limit configuration for a client key, when overridden.
///
/// Only [`RateLimitKey::Client`] can carry an override: the map is keyed by
/// client id, and matching it against a tenant or IP key would apply one
/// client's quota to an unrelated principal that happens to share the string.
///
/// The burst is scaled by the same factor as the rate, so a client granted 10x
/// the throughput also gets 10x the burst window rather than inheriting a burst
/// sized for the default rate.
fn client_rps_override(
    state: &AppState,
    key: &RateLimitKey,
) -> Option<crate::security::RateLimitConfig> {
    let RateLimitKey::Client(id) = key else {
        return None;
    };
    let inner = state.snapshot();
    let security = &inner.config.security;
    let rps = security.rate_limit_clients.get(id).copied()?;
    if rps == 0 {
        return None;
    }
    let default_rps = security.rate_limit_rps.max(1);
    let burst = security
        .rate_limit_burst
        .saturating_mul(rps)
        .checked_div(default_rps)
        .unwrap_or(rps)
        .max(rps);
    Some(crate::security::RateLimitConfig {
        requests_per_second: rps,
        burst,
    })
}

/// Rate limiting middleware: checks rate limiter before processing.
/// Returns 429 with Retry-After header when rate exceeded.
pub(crate) async fn rate_limit_check_middleware(
    State(state): State<Arc<AppState>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let path = request.uri().path();
    if matches!(path, "/health" | "/metrics" | "/live" | "/ready") {
        return next.run(request).await;
    }

    let limiter = match &state.security.rate_limiter {
        Some(l) => l,
        None => return next.run(request).await,
    };

    let key = if let Some(vk) = request
        .extensions()
        .get::<crate::auth::virtual_keys::VirtualKeyContext>()
    {
        RateLimitKey::Tenant(format!("vk:{}", vk.key_id))
    } else if let Some(claims) = request.extensions().get::<crate::auth::GrobClaims>() {
        // Prefer the OIDC client when asked to: `sub` is the end user, so a
        // per-subject bucket does not bound what one application can send.
        // Falls back to the tenant when the token carries no client claim, so
        // enabling this cannot lump unrelated callers together.
        match client_rate_limit_key(&state, claims) {
            Some(key) => key,
            None => RateLimitKey::Tenant(claims.tenant_id().to_string()),
        }
    } else if let Some(credential) = extract_api_credential(request.headers()) {
        // Hash rather than store the raw credential: this key lives in the
        // bucket map for up to ten idle minutes and derives `Debug`, so a
        // future log line or panic message would otherwise print a usable API
        // key. The digest partitions callers identically.
        RateLimitKey::Tenant(format!("cred:{}", hash_credential(credential)))
    } else {
        RateLimitKey::Ip("anonymous".to_string())
    };

    // Default quota, unless a per-client override replaces it below.
    let default_config = crate::security::RateLimitConfig {
        requests_per_second: state.snapshot().config.security.rate_limit_rps,
        burst: state.snapshot().config.security.rate_limit_burst,
    };
    let mut effective_limit = advertised_quota(&default_config);
    let mut effective_window = window_seconds(&default_config);

    // A per-client override replaces the default rate for that bucket only,
    // keeping the deployment's configured burst.
    let (allowed, remaining, reset_after) = match client_rps_override(&state, &key) {
        Some(config) => {
            effective_limit = advertised_quota(&config);
            effective_window = window_seconds(&config);
            limiter.check_with_config(&key, config).await
        }
        None => limiter.check(&key).await,
    };

    if !allowed {
        metrics::counter!("grob_ratelimit_rejected_total").increment(1);
        let retry_after = reset_after
            .map(|d| d.as_secs().max(1).to_string())
            .unwrap_or_else(|| "1".to_string());
        let mut response = Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .header("Retry-After", &retry_after)
            .header("Content-Type", "application/json")
            .body(Body::from(
                r#"{"error":{"type":"rate_limit_error","message":"Rate limit exceeded. Please slow down."}}"#,
            ))
            // All header values are static ASCII; builder cannot fail here.
            .unwrap_or_else(|_| {
                Response::new(Body::from(r#"{"error":{"type":"rate_limit_error","message":"Rate limit exceeded."}}"#))
            });
        apply_ratelimit_headers(response.headers_mut(), effective_limit, 0, effective_window);
        return response;
    }

    // Advertise the quota on the *successful* path too: a client that only
    // learns its budget from a 429 has already been throttled, which is exactly
    // the outcome these fields exist to avoid.
    let mut response = next.run(request).await;
    apply_ratelimit_headers(
        response.headers_mut(),
        effective_limit,
        remaining,
        effective_window,
    );
    response
}

/// Security headers middleware: applies OWASP security headers to all responses.
pub(crate) async fn security_headers_response_middleware(
    request: Request<Body>,
    next: Next,
) -> Response {
    let response = next.run(request).await;
    let config = SecurityHeadersConfig::api_mode();
    apply_security_headers(response, &config)
}

/// Marker inserted into response extensions by handlers that already wrote
/// an audit entry. The audit middleware skips logging when present so that
/// the dispatch pipeline (which audits with rich DLP and token-count context)
/// is the source of truth for request-lifecycle entries on the hot path.
///
/// Endpoints that bypass dispatch entirely (oauth handlers, config API,
/// errors raised in middleware before dispatch) leave this marker absent
/// and are audited centrally by the middleware.
#[derive(Clone, Debug)]
pub struct AuditedAlready;

/// Inputs captured by the audit middleware before the handler runs.
///
/// Stored on the request side so post-handler audit emission can rebuild
/// the entry without re-reading consumed request state.
pub struct AuditMiddlewareCapture {
    /// HTTP method of the request.
    pub method: axum::http::Method,
    /// Path component of the request URI.
    pub path: String,
    /// Correlation ID resolved from the `RequestId` extension.
    pub request_id: String,
    /// Tenant identifier from JWT / virtual key, or empty.
    pub tenant_id: String,
    /// Client IP from `X-Forwarded-For` or `"unknown"`.
    pub client_ip: String,
    /// Wall-clock instant the middleware observed the request.
    pub started_at: std::time::Instant,
}

/// Pulls the captured request context that `audit_log_layer` snapshots
/// before the handler runs.
pub fn capture_audit_input(request: &Request<Body>) -> AuditMiddlewareCapture {
    let request_id = request
        .extensions()
        .get::<RequestId>()
        .map(|r| r.0.clone())
        .unwrap_or_default();

    let tenant_id = if let Some(vk) = request
        .extensions()
        .get::<crate::auth::virtual_keys::VirtualKeyContext>()
    {
        vk.tenant_id.clone()
    } else if let Some(claims) = request.extensions().get::<crate::auth::GrobClaims>() {
        claims.tenant_id().to_string()
    } else {
        String::new()
    };

    AuditMiddlewareCapture {
        method: request.method().clone(),
        path: request.uri().path().to_string(),
        request_id,
        tenant_id,
        client_ip: extract_client_ip(request.headers()),
        started_at: std::time::Instant::now(),
    }
}

/// Emits an `AuditEvent::RequestProcessed` entry from the captured request
/// context plus the post-handler response. Returns `true` when an entry
/// was written, `false` when the response carried [`AuditedAlready`] (in
/// which case the dispatch pipeline already wrote a richer entry).
///
/// Extracted from the audit-log middleware layer so it can be unit-tested without
/// constructing a full `AppState`.
pub fn emit_request_processed(
    audit_log: &crate::security::AuditLog,
    capture: &AuditMiddlewareCapture,
    response: &Response,
    policy_revision: &str,
) -> bool {
    if response.extensions().get::<AuditedAlready>().is_some() {
        return false;
    }

    let status = response.status();
    let duration_ms = capture.started_at.elapsed().as_millis() as u64;

    let provider = response
        .headers()
        .get("x-ai-provider")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let model = response
        .headers()
        .get("x-ai-model")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let error_variant = response
        .extensions()
        .get::<super::error::ErrorVariantTag>()
        .map(|tag| tag.0.clone());

    let backend = if !provider.is_empty() {
        provider
    } else if let Some(ref tag) = error_variant {
        format!("ERROR:{}:{}", tag, status.as_u16())
    } else if status.is_success() {
        format!("{} {}", capture.method, capture.path)
    } else {
        format!("STATUS:{}", status.as_u16())
    };

    let tenant_for_entry = if capture.tenant_id.is_empty() {
        capture.client_ip.as_str()
    } else {
        capture.tenant_id.as_str()
    };

    let mut builder = super::AuditEntryBuilder::new(
        tenant_for_entry,
        crate::security::audit_log::AuditEvent::RequestProcessed,
        &backend,
        &capture.client_ip,
        duration_ms,
    );

    builder = builder.policy_revision(policy_revision);

    if !model.is_empty() {
        builder = builder.model(model);
    }

    // Risk level: low for 2xx, medium for 4xx, high for 5xx — matches
    // the EU AI Act Article 14 escalation threshold defaults.
    let risk = if status.is_server_error() {
        crate::security::audit_log::RiskLevel::High
    } else if status.is_client_error() {
        crate::security::audit_log::RiskLevel::Medium
    } else {
        crate::security::audit_log::RiskLevel::Low
    };
    builder = builder.risk(risk);

    if let Some(tag) = error_variant {
        builder = builder.dlp_rules(vec![format!(
            "request_error:{}:status={}",
            tag,
            status.as_u16()
        )]);
    }

    if let Err(e) = audit_log.write(builder.build()) {
        tracing::error!(
            error = %e,
            request_id = %capture.request_id,
            "audit middleware: write failed"
        );
    }
    true
}

/// Audit-log middleware: emits `AuditEvent::RequestProcessed` for every HTTP
/// request that flows through the server.
///
/// Wraps every endpoint, including the OAuth, config, and health surfaces
/// that previously bypassed audit entirely. Captures request method, path,
/// status, latency, error variant tag (when 4xx/5xx), tenant identifier
/// (from JWT claims or virtual key context), client IP, and the upstream
/// provider name when set on the response by the dispatch pipeline.
///
/// Skips logging when the dispatch pipeline has already written a richer
/// audit entry (signalled by the [`AuditedAlready`] marker in response
/// extensions). Health and metrics endpoints are excluded to avoid
/// flooding the journal with unauthenticated probe traffic.
pub(crate) async fn audit_log_layer(
    State(state): State<Arc<AppState>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let path = request.uri().path();
    if matches!(path, "/health" | "/live" | "/ready" | "/metrics") {
        return next.run(request).await;
    }

    let capture = capture_audit_input(&request);
    let response = next.run(request).await;

    if let Some(ref audit_log) = state.security.audit_log {
        // Read the snapshot after the handler so the recorded revision is the
        // one the request was actually served under.
        emit_request_processed(
            audit_log,
            &capture,
            &response,
            state.snapshot().policy_revision.full(),
        );
    }

    response
}

/// Returns the tenant id derived from authentication context or headers.
///
/// Mirrors `handlers::extract_tenant_id` but uses request extensions /
/// headers directly so middleware can short-circuit before the handler.
fn middleware_tenant_id(request: &Request<Body>) -> Option<String> {
    if let Some(vk) = request
        .extensions()
        .get::<crate::auth::virtual_keys::VirtualKeyContext>()
    {
        return Some(vk.tenant_id.clone());
    }
    if let Some(claims) = request.extensions().get::<crate::auth::GrobClaims>() {
        return Some(claims.tenant_id().to_string());
    }
    request
        .headers()
        .get("x-tenant-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Enforces `[security] strict_tenant`.
///
/// When the flag is enabled, requests that fail to resolve a tenant id
/// (no virtual-key binding, no JWT `tenant` claim, no `X-Tenant-ID`
/// header) are rejected with HTTP 400 and a structured JSON body. Health
/// and OAuth endpoints are exempt because they are dispatched before any
/// tenant context exists.
pub(crate) async fn tenant_required_middleware(
    State(state): State<Arc<AppState>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let path = request.uri().path();
    if matches!(
        path,
        "/health" | "/live" | "/ready" | "/metrics" | "/auth/callback" | "/api/oauth/callback"
    ) {
        return next.run(request).await;
    }

    let inner = state.snapshot();
    if !inner.config.security.strict_tenant {
        return next.run(request).await;
    }

    if middleware_tenant_id(&request).is_some() {
        return next.run(request).await;
    }

    let body = Json(serde_json::json!({
        "error": {
            "type": "missing_tenant",
            "message": "X-Tenant-ID header or JWT tenant claim required when [security] strict_tenant=true"
        }
    }));
    (StatusCode::BAD_REQUEST, body).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Per-client rate limiting ──────────────────────────────────

    /// Minimal config with the security knobs under test.
    fn rl_config(extra: &str) -> crate::cli::AppConfig {
        let toml = format!(
            r#"
[server]
host = "127.0.0.1"
port = 18098

[router]
default = "alpha"

[[providers]]
name = "mock"
provider_type = "openai"
auth_type = "apikey"
api_key = "sk-test"
base_url = "http://127.0.0.1:1"
models = ["alpha"]

[[models]]
name = "alpha"
[[models.mappings]]
priority = 1
provider = "mock"
actual_model = "alpha"

[security]
rate_limit_rps = 10
rate_limit_burst = 20
{extra}
"#
        );
        crate::cli::AppConfig::from_content(&toml, "rate_limit_client_test").expect("config parses")
    }

    fn state_for(extra: &str) -> Arc<AppState> {
        crate::server::test_app_state(rl_config(extra), crate::providers::ProviderRegistry::new())
    }

    fn claims_with_azp(sub: &str, azp: Option<&str>) -> crate::auth::GrobClaims {
        crate::auth::GrobClaims {
            sub: sub.to_string(),
            azp: azp.map(str::to_string),
            ..Default::default()
        }
    }

    /// Disabled by default: the key must stay the tenant.
    ///
    /// Turning this on changes who gets throttled, so it must never happen
    /// implicitly on an existing deployment.
    #[tokio::test]
    async fn client_key_is_not_used_unless_enabled() {
        let state = state_for("");
        let claims = claims_with_azp("user-1", Some("my-app"));
        assert!(
            client_rate_limit_key(&state, &claims).is_none(),
            "per-client keying must be opt-in"
        );
    }

    /// Enabled: two users of one client share a bucket.
    ///
    /// This is the entire point. Keyed by `sub`, an application serving many
    /// users gets one bucket each and is not bounded at all.
    #[tokio::test]
    async fn enabled_keys_two_users_of_one_client_together() {
        let state = state_for("rate_limit_by_client = true");
        let a = client_rate_limit_key(&state, &claims_with_azp("user-1", Some("my-app")));
        let b = client_rate_limit_key(&state, &claims_with_azp("user-2", Some("my-app")));

        assert_eq!(
            a,
            Some(crate::security::RateLimitKey::Client("my-app".to_string()))
        );
        assert_eq!(a, b, "two users of the same client must share one bucket");
    }

    /// Different clients stay separate even for the same user.
    #[tokio::test]
    async fn enabled_keeps_distinct_clients_apart() {
        let state = state_for("rate_limit_by_client = true");
        let a = client_rate_limit_key(&state, &claims_with_azp("user-1", Some("app-a")));
        let b = client_rate_limit_key(&state, &claims_with_azp("user-1", Some("app-b")));
        assert_ne!(
            a, b,
            "one user acting through two clients must not share a bucket"
        );
    }

    /// A token with no client claim falls back to the tenant key.
    ///
    /// Enabling the feature must not silently merge self-signed tokens, API
    /// keys or anonymous callers into one shared bucket.
    #[tokio::test]
    async fn token_without_client_claim_falls_back_to_tenant() {
        let state = state_for("rate_limit_by_client = true");
        assert!(
            client_rate_limit_key(&state, &claims_with_azp("user-1", None)).is_none(),
            "no client claim means no client bucket"
        );
    }

    /// No override configured → no per-key config, so the default applies.
    #[tokio::test]
    async fn no_override_uses_the_default_rate() {
        let state = state_for("rate_limit_by_client = true");
        let key = crate::security::RateLimitKey::Client("unlisted".to_string());
        assert!(client_rps_override(&state, &key).is_none());
    }

    /// A configured override applies its rate and scales the burst with it.
    ///
    /// A client granted 10x throughput but left with the default burst would be
    /// throttled on exactly the traffic shape the override was meant to allow.
    #[tokio::test]
    async fn override_applies_rate_and_scales_burst() {
        let state = state_for(
            "rate_limit_by_client = true\n\n[security.rate_limit_clients]\n\"batch\" = 100",
        );
        let key = crate::security::RateLimitKey::Client("batch".to_string());
        let config = client_rps_override(&state, &key).expect("override must be found");

        assert_eq!(config.requests_per_second, 100);
        // default burst 20 at default rps 10 → 10x the rate means 10x the burst.
        assert_eq!(config.burst, 200, "burst must scale with the granted rate");
    }

    /// The advertised window is how long a full burst takes to accrue.
    ///
    /// A token bucket has no fixed window; this is the closest honest number a
    /// client can pace itself against.
    #[test]
    fn window_seconds_reports_burst_refill_time() {
        let cfg = |rps, burst| crate::security::RateLimitConfig {
            requests_per_second: rps,
            burst,
        };
        // 20 tokens accruing at 10/s take 2 s to refill.
        assert_eq!(window_seconds(&cfg(10, 20)), 2);
        // Sub-second windows round up: the field is a non-zero integer.
        assert_eq!(window_seconds(&cfg(100, 10)), 1);
        // Degenerate config must not divide by zero.
        assert_eq!(window_seconds(&cfg(0, 0)), 1);
    }

    /// The advertised quota is the bucket capacity, so `remaining` can never
    /// exceed it.
    ///
    /// Advertising the refill rate instead produced `limit=10, remaining=19`,
    /// which is unusable: a client cannot pace itself against a budget its own
    /// balance exceeds.
    #[test]
    fn advertised_quota_is_never_below_remaining() {
        let cfg = crate::security::RateLimitConfig {
            requests_per_second: 10,
            burst: 20,
        };
        let quota = advertised_quota(&cfg);
        assert_eq!(quota, 20, "the quota is the bucket capacity");
        assert!(
            quota >= cfg.burst,
            "remaining is capped at burst, so the advertised quota must cover it"
        );

        // Burst unset (0) must fall back to the rate rather than advertise zero.
        let no_burst = crate::security::RateLimitConfig {
            requests_per_second: 7,
            burst: 0,
        };
        assert_eq!(advertised_quota(&no_burst), 7);
    }

    /// Quota fields must be emitted in both the IETF and de-facto spellings.
    #[test]
    fn ratelimit_headers_carry_both_spellings() {
        let mut headers = HeaderMap::new();
        apply_ratelimit_headers(&mut headers, 100, 87, 60);

        // IETF structured fields (draft-ietf-httpapi-ratelimit-headers).
        assert_eq!(
            headers.get("ratelimit-policy").unwrap(),
            "\"default\";q=100;w=60"
        );
        assert_eq!(headers.get("ratelimit").unwrap(), "\"default\";r=87;t=60");

        // De-facto headers, which is what clients actually parse today.
        assert_eq!(headers.get("x-ratelimit-limit").unwrap(), "100");
        assert_eq!(headers.get("x-ratelimit-remaining").unwrap(), "87");
        assert_eq!(headers.get("x-ratelimit-reset").unwrap(), "60");
    }

    /// With no quota configured, nothing must be advertised.
    ///
    /// Emitting `limit=0` would tell a client it may never send a request,
    /// which is the opposite of "unlimited".
    #[test]
    fn no_quota_advertises_nothing() {
        let mut headers = HeaderMap::new();
        apply_ratelimit_headers(&mut headers, 0, 0, 1);
        assert!(
            headers.is_empty(),
            "an unconfigured limiter must not advertise a zero quota"
        );
    }

    /// A raw API key must never become the bucket key.
    ///
    /// Bucket keys live in memory for up to ten idle minutes and `RateLimitKey`
    /// derives `Debug`, so storing the credential verbatim would put a usable
    /// secret one stray log line or panic message away from disclosure.
    #[test]
    fn api_credential_is_hashed_not_stored_verbatim() {
        let secret = "sk-live-super-secret-value";
        let hashed = hash_credential(secret);

        assert!(
            !hashed.contains(secret),
            "the digest must not contain the credential"
        );
        assert_eq!(hashed.len(), 64, "sha-256 hex is 64 chars");
        assert_eq!(
            hashed,
            hash_credential(secret),
            "hashing must be stable, or a caller would get a new bucket per request"
        );
        assert_ne!(
            hashed,
            hash_credential("sk-live-super-secret-valuf"),
            "distinct credentials must land in distinct buckets"
        );
    }

    /// An override must never be applied to a tenant or IP key.
    ///
    /// The map is keyed by client id; matching it against a tenant that happens
    /// to share the string would hand one principal another's quota.
    #[tokio::test]
    async fn override_never_applies_to_a_tenant_or_ip_key() {
        let state = state_for(
            "rate_limit_by_client = true\n\n[security.rate_limit_clients]\n\"batch\" = 100",
        );
        assert!(
            client_rps_override(
                &state,
                &crate::security::RateLimitKey::Tenant("batch".to_string())
            )
            .is_none(),
            "a tenant named like a client must not inherit its quota"
        );
        assert!(client_rps_override(
            &state,
            &crate::security::RateLimitKey::Ip("batch".to_string())
        )
        .is_none());
    }

    #[test]
    fn test_constant_time_eq_same() {
        assert!(constant_time_eq("secret", "secret"));
    }

    #[test]
    fn test_constant_time_eq_different() {
        assert!(!constant_time_eq("secret", "other"));
    }

    #[test]
    fn test_constant_time_eq_different_length() {
        assert!(!constant_time_eq("short", "longer_string"));
    }

    #[test]
    fn test_constant_time_eq_empty() {
        assert!(constant_time_eq("", ""));
    }

    #[test]
    fn test_constant_time_eq_hashed_same() {
        assert!(constant_time_eq_hashed("s3cr3t-token", "s3cr3t-token"));
        assert!(constant_time_eq_hashed("", ""));
    }

    #[test]
    fn test_constant_time_eq_hashed_different_same_length() {
        assert!(!constant_time_eq_hashed("token-aaaa", "token-bbbb"));
    }

    #[test]
    fn test_constant_time_eq_hashed_different_length_rejected() {
        // The length-hiding variant must still reject mismatched-length inputs;
        // it just does so without an early-return that leaks the length.
        assert!(!constant_time_eq_hashed("x", "s3cr3t-token"));
        assert!(!constant_time_eq_hashed("s3cr3t-token", ""));
    }

    #[test]
    fn test_extract_client_ip_from_forwarded() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "1.2.3.4, 5.6.7.8".parse().unwrap());
        assert_eq!(extract_client_ip(&headers), "1.2.3.4");
    }

    #[test]
    fn test_extract_client_ip_single() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "10.0.0.1".parse().unwrap());
        assert_eq!(extract_client_ip(&headers), "10.0.0.1");
    }

    #[test]
    fn test_extract_client_ip_missing() {
        let headers = HeaderMap::new();
        assert_eq!(extract_client_ip(&headers), "unknown");
    }

    #[test]
    fn test_extract_api_credential_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer sk-test-key".parse().unwrap());
        assert_eq!(extract_api_credential(&headers), Some("sk-test-key"));
    }

    #[test]
    fn test_extract_api_credential_x_api_key() {
        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", "my-key".parse().unwrap());
        assert_eq!(extract_api_credential(&headers), Some("my-key"));
    }

    #[test]
    fn test_extract_api_credential_bearer_takes_priority() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer bearer-key".parse().unwrap());
        headers.insert("x-api-key", "api-key".parse().unwrap());
        assert_eq!(extract_api_credential(&headers), Some("bearer-key"));
    }

    #[test]
    fn test_extract_api_credential_no_headers() {
        let headers = HeaderMap::new();
        assert_eq!(extract_api_credential(&headers), None);
    }

    #[test]
    fn test_apply_transparency_headers() {
        let mut headers = HeaderMap::new();
        apply_transparency_headers(&mut headers, "anthropic", "claude-3", "req-123");
        assert_eq!(headers.get("x-ai-provider").unwrap(), "anthropic");
        assert_eq!(headers.get("x-ai-model").unwrap(), "claude-3");
        assert_eq!(headers.get("x-grob-audit-id").unwrap(), "req-123");
        assert_eq!(headers.get("x-ai-generated").unwrap(), "true");
    }
}

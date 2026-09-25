//! Authenticates agents before resolving and injecting service credentials.

use super::AppState;
use crate::credentials::{config::Injection, filter::EchoFilter, CredentialError};
use axum::{
    body::Body,
    extract::{OriginalUri, Path, State},
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use base64::Engine;
use futures::StreamExt;
use std::{collections::HashMap, sync::Arc};

impl IntoResponse for CredentialError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::Denied => StatusCode::FORBIDDEN,
            Self::Changed => StatusCode::CONFLICT,
            _ => StatusCode::SERVICE_UNAVAILABLE,
        };
        (status, Json(serde_json::json!({"error": self.to_string()}))).into_response()
    }
}

pub(super) async fn dispatch(
    State(state): State<Arc<AppState>>,
    Path(params): Path<HashMap<String, String>>,
    OriginalUri(uri): OriginalUri,
    request: Request<Body>,
) -> Result<Response, CredentialError> {
    let inner = state.snapshot();
    let service = params.get("service").ok_or(CredentialError::Denied)?;
    let binding = inner
        .config
        .credential_services
        .iter()
        .find(|b| &b.id == service)
        .ok_or(CredentialError::Denied)?;
    let url = authorize(binding, &uri, &request)?;
    let vk = request.extensions().get::<crate::auth::VirtualKeyContext>();
    if let Err(response) = enforce_limits(&state, &inner, binding, vk).await {
        return Ok(response);
    }
    let client = crate::credentials::transport::client(&url, &binding.allowed_ips)?;
    let method = request.method().clone();
    let content_type = safe_content_type(request.headers());
    let body = axum::body::to_bytes(request.into_body(), 2 * 1024 * 1024)
        .await
        .map_err(|_| CredentialError::Denied)?;
    let broker = inner
        .credential_brokers
        .get(service)
        .ok_or(CredentialError::Denied)?;
    let record = broker.resolve(state.grob_store.clone(), binding).await?;
    let bundle = record.bundle.as_ref().ok_or(CredentialError::Unavailable)?;
    let (header_name, header, filter) = authentication(bundle, &binding.injection)?;
    tracing::info!(service = %binding.id, tenant = %binding.tenant, authority = ?record.authority, generation = %record.generation, recovery = record.recovery, "credential dispatch");
    let guard = super::handlers::ActiveRequestGuard::new(&state);
    // Only selected media headers survive; caller auth, cookies, forwarding and framing do not.
    let response = client
        .request(method, url)
        .header("content-type", content_type)
        .header("accept-encoding", "identity")
        .header(header_name, header)
        .body(body)
        .send()
        .await
        .map_err(|_| CredentialError::Unavailable)?;
    filter_response(response, filter, guard)
}

fn authorize(
    binding: &crate::credentials::config::ServiceBinding,
    uri: &axum::http::Uri,
    request: &Request<Body>,
) -> Result<reqwest::Url, CredentialError> {
    let service = &binding.id;
    let vk = request.extensions().get::<crate::auth::VirtualKeyContext>();
    let jwt = request.extensions().get::<crate::auth::GrobClaims>();
    let (tenant, identity) = if let Some(vk) = vk {
        // Model/provider-scoped keys must not gain a route around their existing restrictions.
        if vk.allowed_models.is_some() || !vk.allowed_providers.is_empty() {
            return Err(CredentialError::Denied);
        }
        (vk.tenant_id.as_str(), format!("key:{}", vk.key_id))
    } else if let Some(jwt) = jwt {
        (jwt.tenant_id(), format!("jwt:{}", jwt.sub))
    } else {
        return Err(CredentialError::Denied);
    };
    if tenant != binding.tenant
        || !binding.agents.contains(&identity)
        || binding
            .expires_at
            .is_some_and(|e| crate::credentials::now() >= e)
    {
        return Err(CredentialError::Denied);
    }
    let prefix = format!("/v1/services/{service}");
    let path = uri
        .path()
        .strip_prefix(&prefix)
        .ok_or(CredentialError::Denied)?;
    let path = if path.is_empty() { "/" } else { path };
    if uri.query().is_some()
        || !crate::credentials::config::canonical_path(path)
        || !binding.paths.iter().any(|p| p == path)
        || !binding
            .methods
            .iter()
            .any(|m| m == request.method().as_str())
    {
        return Err(CredentialError::Denied);
    }
    let mut url = crate::credentials::transport::endpoint(&binding.origin, &binding.allowed_ips)?;
    url.set_path(path);
    Ok(url)
}

async fn enforce_limits(
    state: &Arc<AppState>,
    inner: &Arc<super::ReloadableState>,
    binding: &crate::credentials::config::ServiceBinding,
    vk: Option<&crate::auth::VirtualKeyContext>,
) -> Result<(), Response> {
    let service = &binding.id;
    let tenant = binding.tenant.as_str();
    if super::check_budget_for_tenant(state, inner, "credential_gateway", service, Some(tenant))
        .await
        .is_err()
    {
        return Err((StatusCode::PAYMENT_REQUIRED, "budget exceeded").into_response());
    }
    if let Some(limit) = vk.and_then(|v| v.budget_usd) {
        let budget = &inner.config.budget;
        let limit =
            crate::security::replica_budget_share(limit, budget.replicas, budget.margin_percent);
        let tracker = state.observability.spend_tracker.lock().await;
        if tracker
            .check_tenant_budget(
                Some(tenant),
                "credential_gateway",
                service,
                limit,
                None,
                None,
            )
            .is_err()
        {
            return Err((StatusCode::PAYMENT_REQUIRED, "budget exceeded").into_response());
        }
    }
    if let Some(key) = vk.filter(|v| v.rate_limit_rps.is_some_and(|rps| rps > 0)) {
        let security = &inner.config.security;
        let rps = crate::security::replica_share(
            key.rate_limit_rps.unwrap_or(0),
            security.rate_limit_replicas,
            security.rate_limit_margin_percent,
        );
        let bucket =
            crate::security::RateLimitKey::Tenant(format!("credential-key:{}", key.key_id));
        if !state
            .policy_rate_limiter
            .check_with_config(
                &bucket,
                crate::security::RateLimitConfig {
                    requests_per_second: rps,
                    burst: rps,
                },
            )
            .await
            .0
        {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                [("retry-after", "1")],
                "agent rate limit exceeded",
            )
                .into_response());
        }
    }
    Ok(())
}

fn authentication(
    bundle: &crate::credentials::record::Bundle,
    injection: &Injection,
) -> Result<(String, reqwest::header::HeaderValue, EchoFilter), CredentialError> {
    let (header_name, header_value) = match injection {
        Injection::Bearer => (
            "authorization".to_owned(),
            format!("Bearer {}", bundle.token),
        ),
        Injection::Basic => {
            let pair = zeroize::Zeroizing::new(format!("{}:{}", bundle.username, bundle.password));
            (
                "authorization".to_owned(),
                format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD.encode(pair.as_bytes())
                ),
            )
        }
        Injection::Header { name } => (name.clone(), bundle.token.clone()),
    };
    let header_value = zeroize::Zeroizing::new(header_value);
    let mut header = reqwest::header::HeaderValue::from_str(&header_value)
        .map_err(|_| CredentialError::Denied)?;
    header.set_sensitive(true);
    let mut values = vec![
        bundle.token.clone(),
        bundle.username.clone(),
        bundle.password.clone(),
        header_value.to_string(),
    ];
    if matches!(injection, Injection::Basic) {
        values.push(header_value.trim_start_matches("Basic ").to_owned());
        values.push(format!("{}:{}", bundle.username, bundle.password));
    }
    Ok((header_name, header, EchoFilter::new(values)))
}

fn filter_response(
    response: reqwest::Response,
    mut filter: EchoFilter,
    guard: super::handlers::ActiveRequestGuard,
) -> Result<Response, CredentialError> {
    if response.status().is_redirection()
        || response
            .headers()
            .get("content-encoding")
            .is_some_and(|v| v != "identity")
    {
        return Err(CredentialError::Denied);
    }
    let status = response.status();
    let content_type = safe_content_type(response.headers());
    let mut stream = response.bytes_stream();
    let filtered = async_stream::try_stream! {
        let _guard = guard;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| std::io::Error::other("upstream stream failed"))?;
            for part in chunk.chunks(16384) {
                let clean = filter.push(part, false);
                if !clean.is_empty() { yield axum::body::Bytes::from(clean); }
            }
        }
        let clean = filter.push(&[], true);
        if !clean.is_empty() { yield axum::body::Bytes::from(clean); }
    };
    let filtered: std::pin::Pin<
        Box<dyn futures::Stream<Item = Result<axum::body::Bytes, std::io::Error>> + Send>,
    > = Box::pin(filtered);
    let body = Body::from_stream(filtered);
    Response::builder()
        .status(status)
        .header("content-type", content_type)
        .header("cache-control", "no-store")
        .body(body)
        .map_err(|_| CredentialError::Unavailable)
}

fn safe_content_type(headers: &axum::http::HeaderMap) -> &'static str {
    match headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
    {
        Some("application/json") => "application/json",
        Some("text/event-stream") => "text/event-stream",
        Some("text/plain") => "text/plain",
        Some("application/x-www-form-urlencoded") => "application/x-www-form-urlencoded",
        _ => "application/octet-stream",
    }
}

pub(super) async fn status(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<super::rpc::auth::CallerIdentity>,
) -> Result<Json<serde_json::Value>, CredentialError> {
    if !caller.role.has_at_least(super::rpc::types::Role::Admin) {
        return Err(CredentialError::Denied);
    }
    let bindings = state.snapshot().config.credential_services.clone();
    let statuses = tokio::task::spawn_blocking(move || bindings.iter().map(|binding| {
        match state.grob_store.credential_read(&binding.tenant, &binding.id) {
            Ok(record) => serde_json::json!({"service":binding.id, "authority":record.authority, "generation":record.generation, "revoked":record.revoked, "verified_at":record.verified_at, "expires_at":record.expires_at, "state": record.state(binding, crate::credentials::now())}),
            Err(_) => serde_json::json!({"service":binding.id,"state":"unavailable"}),
        }
    }).collect::<Vec<_>>()).await.map_err(|_| CredentialError::Storage)?;
    Ok(Json(serde_json::json!({"services":statuses})))
}

#[cfg(test)]
mod tests;

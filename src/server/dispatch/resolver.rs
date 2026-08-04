//! Provider selection: pick the next usable mapping from the priority list.
//!
//! Extracted from `provider_loop.rs` to keep the fallback orchestration focused
//! on the loop shape. The two concerns live next to each other but read
//! independently: [`resolve_provider`] answers "is this provider available?"
//! and [`try_direct_provider_lookup`] is the backward-compat fallback when
//! no tier/mapping matched.

use std::sync::Arc;

use super::super::{is_auth_revoked_error, RequestError};
use super::retry::{capture_upstream_error, is_upstream_rate_limit};
use super::{DispatchContext, DispatchResult};
use crate::providers::registry::DispatchRejection;
use tracing::info;

/// Returns the provider for a mapping, or `None` if it must be skipped.
///
/// The registry owns composition of provider-level availability and
/// endpoint-level health. This resolver only translates the decision into
/// dispatch logs and rejection metrics.
pub(super) async fn resolve_provider(
    ctx: &DispatchContext<'_>,
    mapping: &crate::cli::ModelMapping,
) -> Option<Arc<dyn crate::providers::LlmProvider>> {
    let result = ctx
        .inner
        .provider_registry
        .provider_for_dispatch(
            &mapping.provider,
            &mapping.actual_model,
            ctx.state.security.provider_availability.as_deref(),
        )
        .await;

    match result {
        Ok(provider) => Some(provider),
        Err(DispatchRejection::ProviderNotRegistered) => {
            info!(
                "Provider {} not found in registry, trying next fallback",
                mapping.provider
            );
            None
        }
        Err(DispatchRejection::ProviderUnavailable) => {
            info!("Provider {} unavailable, skipping", mapping.provider);
            metrics::counter!(
                "grob_circuit_breaker_rejected_total",
                "provider" => mapping.provider.clone()
            )
            .increment(1);
            None
        }
        Err(DispatchRejection::EndpointUnavailable) => {
            info!(
                "Endpoint {}/{} unavailable, skipping",
                mapping.provider, mapping.actual_model
            );
            metrics::counter!(
                "grob_routing_endpoint_cb_rejected_total",
                "provider" => mapping.provider.clone(),
                "model" => mapping.actual_model.clone(),
            )
            .increment(1);
            None
        }
    }
}

/// Backward-compat fallback: try direct model -> provider lookup from the registry.
///
/// Invoked by the provider loop after every mapping in the priority list has
/// been exhausted. Lets a request for `claude-opus-4-7` succeed even when no
/// `[[models.mappings]]` targets it explicitly, as long as the registry can
/// resolve the bare model name.
pub(super) async fn try_direct_provider_lookup(
    ctx: &DispatchContext<'_>,
    request: &crate::models::CanonicalRequest,
    model_name: &str,
    context_guard: Option<crate::server::ContextGuardInfo>,
) -> Result<Option<DispatchResult>, RequestError> {
    let Ok((provider_name, _)) = ctx
        .inner
        .provider_registry
        .provider_and_name_for_model(model_name)
    else {
        return Ok(None);
    };
    let Some(provider) = resolve_provider_name(ctx, &provider_name, model_name).await else {
        return Ok(None);
    };
    info!(
        "Using provider from registry (direct lookup): {}",
        model_name
    );
    let mut fallback_request = request.clone();
    let original_model = fallback_request.model.clone();
    fallback_request.model = model_name.to_string();

    let mut response = provider.send_message(fallback_request).await.map_err(|e| {
        if is_auth_revoked_error(&e) {
            RequestError::AuthRevoked(e.to_string())
        } else if matches!(&e, crate::providers::error::ProviderError::AuthError(_))
            || is_upstream_rate_limit(&e)
        {
            RequestError::from(e)
        } else {
            capture_upstream_error(model_name, &e)
        }
    })?;
    response.model = original_model;

    Ok(Some(DispatchResult::Complete {
        response,
        provider: model_name.to_string(),
        actual_model: model_name.to_string(),
        provider_duration_ms: 0,
        context_guard,
    }))
}

async fn resolve_provider_name(
    ctx: &DispatchContext<'_>,
    provider: &str,
    model: &str,
) -> Option<Arc<dyn crate::providers::LlmProvider>> {
    let mapping = crate::cli::ModelMapping {
        provider: provider.to_string(),
        actual_model: model.to_string(),
        priority: 0,
        inject_continuation_prompt: false,
    };
    resolve_provider(ctx, &mapping).await
}

//! Provider selection: pick the next usable mapping from the priority list.
//!
//! Extracted from `provider_loop.rs` to keep the fallback orchestration focused
//! on the loop shape. The two concerns live next to each other but read
//! independently: [`resolve_provider`] answers "is this provider available?"
//! and [`try_direct_provider_lookup`] is the backward-compat fallback when
//! no tier/mapping matched.

use std::sync::Arc;

use super::{DispatchContext, DispatchResult};
use super::super::AppError;
use tracing::info;

/// Returns the provider for a mapping, or `None` if it must be skipped.
///
/// Checks, in order:
///
/// 1. Provider exists in the registry.
/// 2. `SecurityConfig::provider_scorer` (wraps `CircuitBreakerRegistry`) —
///    if a scorer is enabled, it owns availability decisions.
/// 3. Bare `CircuitBreakerRegistry` — used when no scorer is configured.
/// 4. Routing-layer passive CB (RE-1a, ADR-0018) — per-endpoint, orthogonal
///    to the global per-provider CB above.
///
/// Each rejection path emits a `grob_circuit_breaker_rejected_total` (or
/// `grob_routing_endpoint_cb_rejected_total`) counter for observability.
pub(super) async fn resolve_provider(
    ctx: &DispatchContext<'_>,
    mapping: &crate::cli::ModelMapping,
) -> Option<Arc<dyn crate::providers::LlmProvider>> {
    let provider = ctx
        .inner
        .provider_registry
        .provider(&mapping.provider)
        .or_else(|| {
            info!(
                "Provider {} not found in registry, trying next fallback",
                mapping.provider
            );
            None
        })?;

    // Check availability: scorer (which wraps CB) takes priority over bare CB
    if let Some(ref scorer) = ctx.state.security.provider_scorer {
        if !scorer.can_execute(&mapping.provider).await {
            info!(
                "Provider {} unavailable (scorer/CB), skipping",
                mapping.provider
            );
            metrics::counter!(
                "grob_circuit_breaker_rejected_total",
                "provider" => mapping.provider.clone()
            )
            .increment(1);
            return None;
        }
    } else if let Some(ref cb) = ctx.state.security.circuit_breakers {
        if !cb.can_execute(&mapping.provider).await {
            info!("Circuit breaker open for {}, skipping", mapping.provider);
            metrics::counter!(
                "grob_circuit_breaker_rejected_total",
                "provider" => mapping.provider.clone()
            )
            .increment(1);
            return None;
        }
    }

    // Routing-layer passive CB (RE-1a, ADR-0018). Per-endpoint, orthogonal
    // to the global per-provider security CB above — an endpoint can be
    // down while the provider still has other endpoints up.
    if !ctx
        .inner
        .provider_registry
        .is_endpoint_healthy(&mapping.provider, &mapping.actual_model)
    {
        info!(
            "Endpoint {}/{} tripped by passive CB, skipping",
            mapping.provider, mapping.actual_model
        );
        metrics::counter!(
            "grob_routing_endpoint_cb_rejected_total",
            "provider" => mapping.provider.clone(),
            "model" => mapping.actual_model.clone(),
        )
        .increment(1);
        return None;
    }

    Some(provider)
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
) -> Result<Option<DispatchResult>, AppError> {
    let Ok(provider) = ctx.inner.provider_registry.provider_for_model(model_name) else {
        return Ok(None);
    };
    info!(
        "Using provider from registry (direct lookup): {}",
        model_name
    );
    let mut fallback_request = request.clone();
    let original_model = fallback_request.model.clone();
    fallback_request.model = model_name.to_string();

    let mut response = provider
        .send_message(fallback_request)
        .await
        .map_err(|e| AppError::ProviderError(e.to_string()))?;
    response.model = original_model;

    Ok(Some(DispatchResult::Complete {
        response,
        provider: model_name.to_string(),
        actual_model: model_name.to_string(),
        provider_duration_ms: 0,
    }))
}

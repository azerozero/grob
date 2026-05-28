//! Provider fallback loop: orchestrates the priority-list walk.
//!
//! The hot path of the dispatch pipeline. For each mapping in the sorted
//! priority list this function:
//!
//! 1. Asks [`resolver::resolve_provider`] whether the mapping is usable
//!    (registry + CB + RE-1a passive CB).
//! 2. Checks the tenant / provider / model budget.
//! 3. Emits the `RequestStart` event for `grob watch`.
//! 4. Prepares the provider-specific request (model substitution, DLP,
//!    continuation injection).
//! 5. Dispatches a single attempt through [`retry::dispatch_streaming`] or
//!    [`retry::dispatch_non_streaming`] depending on the request mode.
//! 6. On `RateLimited` tries pool rotation via [`retry::try_rotate_and_retry`].
//! 7. On `AuthRevoked` aborts the cascade (user-actionable 401).
//! 8. Otherwise moves on to the next mapping.
//!
//! After the loop exhausts the list, [`resolver::try_direct_provider_lookup`]
//! offers a backward-compat path for unmapped models. A final audit entry
//! is written before returning `RequestError::ProviderUpstream`.

use super::super::{
    check_budget_for_tenant, format_route_type, inject_continuation_text, is_provider_subscription,
    should_inject_continuation, RequestError,
};
use super::resolver::{resolve_provider, try_direct_provider_lookup};
use super::retry::{
    dispatch_non_streaming, dispatch_streaming, try_rotate_and_retry, ProviderAttempt,
    ProviderLoopAction, StreamingAttempt,
};
use super::{AuditEntry, DispatchContext, DispatchResult};
use crate::models::RouteType;
use tracing::info;

/// Provider loop with fallback and per-provider retry.
pub(super) async fn dispatch_provider_loop(
    ctx: &DispatchContext<'_>,
    request: &mut crate::models::CanonicalRequest,
    sorted_mappings: &[crate::cli::ModelMapping],
    decision: &crate::models::RouteDecision,
    cache_key: &Option<String>,
) -> Result<DispatchResult, RequestError> {
    // Re-sort mappings by adaptive score when scorer is enabled
    let rescored;
    let effective_mappings: &[crate::cli::ModelMapping] =
        if let Some(ref scorer) = ctx.state.security.provider_scorer {
            rescored = scorer.sort_mappings(sorted_mappings.to_vec()).await;
            &rescored
        } else {
            sorted_mappings
        };

    for (idx, mapping) in effective_mappings.iter().enumerate() {
        let Some(provider) = resolve_provider(ctx, mapping).await else {
            continue;
        };

        check_budget_for_tenant(
            ctx.state,
            ctx.inner,
            &mapping.provider,
            &decision.model_name,
            ctx.tenant_id.as_deref(),
        )
        .await?;

        log_dispatch_attempt(ctx, mapping, decision, idx, effective_mappings.len());

        // Emit RequestStart event for `grob watch`.
        ctx.state
            .event_bus
            .emit(crate::features::watch::events::WatchEvent::RequestStart {
                request_id: ctx.req_id.to_string(),
                model: mapping.actual_model.clone(),
                provider: mapping.provider.clone(),
                input_tokens: 0,
                route_type: decision.route_type.to_string(),
                timestamp: chrono::Utc::now(),
            });

        let (provider_request, original_model) =
            prepare_provider_request(ctx, request, mapping, &decision.route_type);

        let is_subscription = is_provider_subscription(ctx.inner, &mapping.provider);

        if let Some(ref trace_id) = ctx.trace_id {
            ctx.state.observability.message_tracer.trace_request(
                trace_id,
                &provider_request,
                &mapping.provider,
                &decision.route_type,
                ctx.is_streaming,
            );
        }

        let result = if ctx.is_streaming {
            dispatch_streaming(
                ctx,
                provider_request,
                provider.as_ref(),
                &StreamingAttempt {
                    mapping,
                    decision,
                    is_subscription,
                },
            )
            .await
        } else {
            dispatch_non_streaming(
                ctx,
                provider_request,
                provider.as_ref(),
                &ProviderAttempt {
                    mapping,
                    decision,
                    cache_key,
                    original_model: &original_model,
                    is_subscription,
                },
            )
            .await
        };

        match result {
            Ok(dispatch_result) => return Ok(dispatch_result),
            Err(ProviderLoopAction::RateLimited) => {
                if let Some(ok) = try_rotate_and_retry(
                    ctx,
                    request,
                    provider.as_ref(),
                    &ProviderAttempt {
                        mapping,
                        decision,
                        cache_key,
                        original_model: &original_model,
                        is_subscription,
                    },
                )
                .await
                {
                    return Ok(ok);
                }
                emit_fallback(
                    ctx,
                    mapping,
                    effective_mappings.get(next_mapping_index(idx)),
                    "rate limited",
                );
                tokio::task::yield_now().await;
                continue;
            }
            Err(ProviderLoopAction::Continue) => {
                emit_fallback(
                    ctx,
                    mapping,
                    effective_mappings.get(next_mapping_index(idx)),
                    "provider error",
                );
                tokio::task::yield_now().await;
                continue;
            }
            Err(ProviderLoopAction::AuthRevoked(msg)) => {
                tracing::error!(
                    provider = %mapping.provider,
                    "OAuth token for provider {} revoked. Run: grob connect --force-reauth",
                    mapping.provider
                );
                // Abort the fallback cascade: this is a user-actionable error,
                // not a transient provider failure.
                return Err(RequestError::AuthRevoked(format!(
                    "OAuth token for provider '{}' revoked. Run: grob connect --force-reauth. Details: {}",
                    mapping.provider, msg
                )));
            }
        }
    }

    // All providers exhausted -- try backward-compat direct lookup
    if let Some(result) = try_direct_provider_lookup(ctx, request, &decision.model_name).await? {
        return Ok(result);
    }

    // Audit: all providers failed
    ctx.log_audit_if_enabled(AuditEntry {
        action: crate::security::audit_log::AuditEvent::Error,
        backend: "NONE",
        dlp_rules: vec![],
        duration_ms: ctx.start_time.elapsed().as_millis() as u64,
        model_name: None,
        token_counts: None,
        risk_level: None,
        dlp_blocked: false,
        dlp_had_injection: false,
        dlp_had_pii: false,
        dlp_had_redact_or_warn: false,
    });

    tracing::error!(
        request_id = ctx.req_id,
        "All provider mappings failed for model: {}",
        decision.model_name
    );
    Err(RequestError::ProviderUpstream {
        provider: "all".to_string(),
        status: 502,
        body: Some(format!(
            "All {} provider mappings failed for model: {}",
            effective_mappings.len(),
            decision.model_name
        )),
    })
}

/// Returns the index of the next mapping to fall back to.
///
/// Extracted so the fallback-index arithmetic in [`dispatch_provider_loop`] is
/// unit-testable without constructing a full [`DispatchContext`].
#[inline]
fn next_mapping_index(idx: usize) -> usize {
    idx + 1
}

/// Returns the ` [n/total]` retry suffix, or an empty string for the first try.
///
/// Extracted so the `idx > 0` boundary in [`log_dispatch_attempt`] is
/// unit-testable without constructing a full [`DispatchContext`].
fn retry_suffix(idx: usize, total: usize) -> String {
    if idx > 0 {
        format!(" [{}/{}]", idx + 1, total)
    } else {
        String::new()
    }
}

/// Log the dispatch attempt info line (route type, stream mode, model -> provider).
fn log_dispatch_attempt(
    ctx: &DispatchContext<'_>,
    mapping: &crate::cli::ModelMapping,
    decision: &crate::models::RouteDecision,
    idx: usize,
    total: usize,
) {
    let retry_info = retry_suffix(idx, total);
    let stream_mode = if ctx.is_streaming { "stream" } else { "sync" };
    let route_type_display = format_route_type(decision);

    info!(
        request_id = ctx.req_id,
        "[{:<15}:{}] {:<25} -> {}/{}{}",
        route_type_display,
        stream_mode,
        ctx.model,
        mapping.provider,
        mapping.actual_model,
        retry_info
    );
}

/// Returns `true` when a continuation prompt should be injected.
///
/// Continuation is injected only when the mapping opts in *and* the request is
/// not a background task. Extracted so the guard in [`prepare_provider_request`]
/// is unit-testable without constructing a full [`DispatchContext`].
#[inline]
fn should_attempt_continuation(inject_continuation_prompt: bool, route_type: &RouteType) -> bool {
    inject_continuation_prompt && *route_type != RouteType::Background
}

/// Clone the request, substitute the actual model, run DLP, and optionally inject continuation.
///
/// Visible to `retry.rs` because pool-rotation retries re-run the pre-flight
/// transformations (DLP, continuation) before the second attempt.
pub(super) fn prepare_provider_request(
    ctx: &DispatchContext<'_>,
    request: &crate::models::CanonicalRequest,
    mapping: &crate::cli::ModelMapping,
    route_type: &RouteType,
) -> (crate::models::CanonicalRequest, String) {
    let mut provider_request = request.clone();
    let original_model = provider_request.model.clone();
    provider_request.model = mapping.actual_model.clone();
    ctx.sanitize_input(&mut provider_request);

    if should_attempt_continuation(mapping.inject_continuation_prompt, route_type) {
        if let Some(last_msg) = provider_request.messages.last_mut() {
            if should_inject_continuation(last_msg) {
                info!(
                    "Injecting continuation prompt for model: {}",
                    mapping.actual_model
                );
                inject_continuation_text(last_msg);
            }
        }
    }

    (provider_request, original_model)
}

/// Emits a fallback event for `grob watch`.
fn emit_fallback(
    ctx: &DispatchContext<'_>,
    from: &crate::cli::ModelMapping,
    next: Option<&crate::cli::ModelMapping>,
    reason: &str,
) {
    if let Some(next) = next {
        ctx.state
            .event_bus
            .emit(crate::features::watch::events::WatchEvent::Fallback {
                request_id: ctx.req_id.to_string(),
                from_provider: from.provider.clone(),
                to_provider: next.provider.clone(),
                reason: reason.to_string(),
                timestamp: chrono::Utc::now(),
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_mapping_index_increments() {
        // `idx + 1`: the `+` → `*` mutant collapses to `idx` (idx*1) and the
        // `+` → `-` mutant points one slot backwards. Both diverge here.
        assert_eq!(next_mapping_index(0), 1);
        assert_eq!(next_mapping_index(1), 2);
        assert_eq!(next_mapping_index(2), 3);
    }

    #[test]
    fn retry_suffix_empty_on_first_attempt() {
        // `idx > 0`: the `>` → `==` mutant would emit a suffix for idx 0.
        assert_eq!(retry_suffix(0, 3), "");
    }

    #[test]
    fn retry_suffix_present_on_retries() {
        // idx 1 is the second attempt → " [2/3]". The `idx > 0` → `idx == 0`
        // mutant would return an empty string here instead.
        assert_eq!(retry_suffix(1, 3), " [2/3]");
        assert_eq!(retry_suffix(2, 3), " [3/3]");
    }

    #[test]
    fn continuation_requires_opt_in_and_non_background() {
        // `inject && route != Background`.
        // The `&&` → `||` mutant injects when only one side holds;
        // the `!=` → `==` mutant injects exactly for the Background route.
        assert!(should_attempt_continuation(true, &RouteType::Default));
        assert!(should_attempt_continuation(true, &RouteType::Think));
        assert!(!should_attempt_continuation(true, &RouteType::Background));
        assert!(!should_attempt_continuation(false, &RouteType::Default));
        assert!(!should_attempt_continuation(false, &RouteType::Background));
    }
}

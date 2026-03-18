use crate::features::dlp::DlpEngine;
use axum::http::HeaderMap;
use std::borrow::Cow;
use std::sync::Arc;
use tracing::info;

use super::{AppError, ReloadableState};

/// Resolve and sort provider mappings for a routing decision.
pub(crate) fn resolve_provider_mappings(
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
        // No explicit [[models]] config — check for pass-through providers
        let gdpr = inner.config.router.gdpr;
        let required_region = inner.config.router.region.as_deref();
        let all_pass_through: Vec<&crate::providers::ProviderConfig> = inner
            .config
            .providers
            .iter()
            .filter(|p| p.is_enabled() && p.pass_through.unwrap_or(false))
            .filter(|p| {
                // GDPR/region filtering for pass-through providers
                if gdpr || required_region.is_some() {
                    let region_filter = required_region.unwrap_or("eu");
                    let provider_region = p.region.as_deref().unwrap_or("global");
                    provider_region == region_filter || provider_region == "global"
                } else {
                    true
                }
            })
            .collect();

        // Smart filtering: prefer providers whose type matches the inferred model family
        let inferred = crate::router::inference::infer_provider_type(&decision.model_name);
        let filtered: Vec<&crate::providers::ProviderConfig> = if let Some(inf) = inferred {
            let matched: Vec<_> = all_pass_through
                .iter()
                .filter(|p| {
                    p.provider_type == inf
                        || (inf == "openai" && p.provider_type == "openrouter")
                        || (inf == "anthropic" && p.provider_type == "openrouter")
                        || (inf == "gemini" && p.provider_type == "openrouter")
                })
                .copied()
                .collect();
            if matched.is_empty() {
                all_pass_through
            } else {
                matched
            }
        } else {
            all_pass_through
        };

        let pass_through_mappings: Vec<crate::cli::ModelMapping> = filtered
            .iter()
            .enumerate()
            .map(|(i, p)| crate::cli::ModelMapping {
                priority: (i as u32) + 1,
                provider: p.name.clone(),
                actual_model: decision.model_name.clone(),
                inject_continuation_prompt: false,
            })
            .collect();

        if pass_through_mappings.is_empty() {
            Err(AppError::RoutingError(format!(
                "Model '{}' is not configured. Add a [[models]] entry in config.toml or set pass_through = true on a provider.",
                decision.model_name
            )))
        } else {
            info!(
                "Pass-through routing '{}' to {} provider(s) (inferred: {:?})",
                decision.model_name,
                pass_through_mappings.len(),
                inferred,
            );
            Ok(pass_through_mappings)
        }
    }
}

/// Format route type for logging
pub(crate) fn format_route_type(decision: &crate::models::RouteDecision) -> String {
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

/// Applies DLP sanitization to a non-streaming response and collects reports.
pub(crate) fn sanitize_provider_response_reported(
    response: &mut crate::providers::ProviderResponse,
    dlp: &Arc<DlpEngine>,
) -> Vec<crate::features::dlp::DlpActionReport> {
    use crate::models::{ContentBlock, KnownContentBlock};
    let mut reports = Vec::new();
    for block in &mut response.content {
        if let ContentBlock::Known(KnownContentBlock::Text { text, .. }) = block {
            let (new_text, r) = dlp.sanitize_response_text_reported(text);
            reports.extend(r);
            if let Cow::Owned(s) = new_text {
                *text = s;
            }
        }
    }
    reports
}

/// Check if message has tool results but no text content
/// (indicates model should continue after tool execution)
pub(crate) fn should_inject_continuation(msg: &crate::models::Message) -> bool {
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
pub(crate) fn inject_continuation_text(msg: &mut crate::models::Message) {
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

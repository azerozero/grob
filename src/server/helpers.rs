use crate::features::dlp::DlpEngine;
use axum::http::HeaderMap;
use std::borrow::Cow;
use std::sync::Arc;
use tracing::info;

use super::{ReloadableState, RequestError};

/// Resolve and sort provider mappings for a routing decision.
pub(crate) fn resolve_provider_mappings(
    inner: &Arc<ReloadableState>,
    headers: &HeaderMap,
    decision: &crate::models::RouteDecision,
) -> Result<Vec<crate::cli::ModelMapping>, RequestError> {
    // Tier-based provider selection (opt-in via [[tiers]] config)
    if let Some(ref tier) = decision.complexity_tier {
        let tier_name = tier.to_string();
        if let Some(tier_cfg) = inner.config.tiers.iter().find(|t| t.name == tier_name) {
            info!(
                "📊 Tier '{}' matched — resolving provider mappings",
                tier_name
            );

            // Look up [[models]] config once so we can pick actual_model per provider.
            let model_config = inner.find_model(&decision.model_name);

            let mut priority: u32 = 0;
            let mappings: Vec<crate::cli::ModelMapping> = tier_cfg
                .providers
                .iter()
                .filter_map(|provider_name| {
                    // Step 1: prefer explicit actual_model from [[models.mappings]].
                    if let Some(mc) = model_config {
                        if let Some(mapping) =
                            mc.mappings.iter().find(|m| m.provider == *provider_name)
                        {
                            info!(
                                "tier {} -> provider {} -> actual_model {} (from [[models]] mapping)",
                                tier_name, provider_name, mapping.actual_model
                            );
                            priority += 1;
                            return Some(crate::cli::ModelMapping {
                                priority,
                                provider: provider_name.clone(),
                                actual_model: mapping.actual_model.clone(),
                                inject_continuation_prompt: mapping.inject_continuation_prompt,
                            });
                        }
                    }

                    // Step 2: provider explicitly lists the model name — use as-is.
                    let provider_supports = inner
                        .config
                        .providers
                        .iter()
                        .find(|p| p.name == *provider_name)
                        .map(|p| {
                            p.models.iter().any(|m| m == &decision.model_name)
                                || p.pass_through.unwrap_or(false)
                        })
                        .unwrap_or(false);

                    if provider_supports {
                        info!(
                            "tier {} -> provider {} -> actual_model {} (provider models list)",
                            tier_name, provider_name, decision.model_name
                        );
                        priority += 1;
                        return Some(crate::cli::ModelMapping {
                            priority,
                            provider: provider_name.clone(),
                            actual_model: decision.model_name.clone(),
                            inject_continuation_prompt: false,
                        });
                    }

                    // Step 3: no resolution — skip this provider to avoid sending an unknown model name.
                    info!(
                        "tier {} -> provider {} SKIP (no resolution for model '{}')",
                        tier_name, provider_name, decision.model_name
                    );
                    None
                })
                .collect();

            if !mappings.is_empty() {
                return Ok(mappings);
            }
            // All tier providers were skipped — fall through to [[models]] / pass-through logic.
            info!(
                "tier {} — all providers skipped, falling back to [[models]] routing",
                tier_name
            );
        }
    }

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
                return Err(RequestError::RoutingError(format!(
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
                return Err(RequestError::RoutingError(format!(
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
        let inferred =
            crate::routing::classify::inference::infer_provider_type(&decision.model_name);
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
            Err(RequestError::RoutingError(format!(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::ProviderRegistry;
    use crate::routing::classify::Router;
    use crate::server::ReloadableState;
    use axum::http::HeaderMap;

    /// Builds a minimal [`ReloadableState`] from a TOML snippet.
    fn make_state(toml: &str) -> Arc<ReloadableState> {
        let config: crate::models::config::AppConfig =
            toml::from_str(toml).expect("valid test TOML");
        let router = Router::new(config.clone());
        let registry = Arc::new(ProviderRegistry::new());
        Arc::new(ReloadableState::new(config, router, registry))
    }

    /// Builds a [`RouteDecision`] with the given model name and tier.
    fn decision(
        model: &str,
        tier: Option<crate::routing::classify::ComplexityTier>,
    ) -> crate::models::RouteDecision {
        crate::models::RouteDecision {
            model_name: model.to_string(),
            route_type: crate::models::RouteType::Default,
            matched_prompt: None,
            complexity_tier: tier,
        }
    }

    // Cas 1: tier match + mapping [[models]] existe pour ce provider
    // → actual_model du mapping est utilisé, pas le model_name brut.
    #[test]
    fn tier_with_model_mapping_uses_actual_model() {
        let toml = r#"
[router]
default = "claude-sonnet-4-6"

[[providers]]
name = "openrouter"
provider_type = "openrouter"
models = []
enabled = true

[[tiers]]
name = "complex"
providers = ["openrouter"]

[[models]]
name = "claude-sonnet-4-6"

[[models.mappings]]
provider = "openrouter"
actual_model = "anthropic/claude-sonnet-4-6"
priority = 1
"#;
        let state = make_state(toml);
        let headers = HeaderMap::new();
        let dec = decision(
            "claude-sonnet-4-6",
            Some(crate::routing::classify::ComplexityTier::Complex),
        );

        let mappings = resolve_provider_mappings(&state, &headers, &dec).expect("should resolve");

        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].provider, "openrouter");
        // Must use the actual_model from [[models.mappings]], not the raw model name.
        assert_eq!(mappings[0].actual_model, "anthropic/claude-sonnet-4-6");
    }

    // Cas 2: tier match + pas de [[models]] mapping mais provider liste le model → used as-is.
    #[test]
    fn tier_without_mapping_but_provider_knows_model_uses_raw_name() {
        let toml = r#"
[router]
default = "claude-sonnet-4-6"

[[providers]]
name = "anthropic"
provider_type = "anthropic"
models = ["claude-sonnet-4-6"]
enabled = true

[[tiers]]
name = "medium"
providers = ["anthropic"]
"#;
        let state = make_state(toml);
        let headers = HeaderMap::new();
        let dec = decision(
            "claude-sonnet-4-6",
            Some(crate::routing::classify::ComplexityTier::Medium),
        );

        let mappings = resolve_provider_mappings(&state, &headers, &dec).expect("should resolve");

        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].provider, "anthropic");
        assert_eq!(mappings[0].actual_model, "claude-sonnet-4-6");
    }

    // Cas 3: tier match + aucun mapping + provider ne connaît pas le model
    // → provider SKIP, fallback sur [[models]] classique.
    #[test]
    fn tier_all_providers_skipped_falls_back_to_models_routing() {
        let toml = r#"
[router]
default = "claude-sonnet-4-6"

[[providers]]
name = "deepinfra"
provider_type = "openai"
models = ["some-other-model"]
enabled = true

[[providers]]
name = "anthropic"
provider_type = "anthropic"
models = ["claude-sonnet-4-6"]
enabled = true

[[tiers]]
name = "trivial"
providers = ["deepinfra"]

[[models]]
name = "claude-sonnet-4-6"

[[models.mappings]]
provider = "anthropic"
actual_model = "claude-sonnet-4-6"
priority = 1
"#;
        let state = make_state(toml);
        let headers = HeaderMap::new();
        let dec = decision(
            "claude-sonnet-4-6",
            Some(crate::routing::classify::ComplexityTier::Trivial),
        );

        // deepinfra is in the tier but doesn't know "claude-sonnet-4-6" and has no mapping.
        // The tier loop produces an empty list → fallback to [[models]] which gives anthropic.
        let mappings =
            resolve_provider_mappings(&state, &headers, &dec).expect("should fallback and resolve");

        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].provider, "anthropic");
        assert_eq!(mappings[0].actual_model, "claude-sonnet-4-6");
    }
}

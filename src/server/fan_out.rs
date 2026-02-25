use crate::cli::{FanOutConfig, FanOutMode, ModelMapping};
use crate::models::AnthropicRequest;
use crate::providers::error::ProviderError;
use crate::providers::{ProviderRegistry, ProviderResponse};
use std::sync::Arc;
use tracing::{info, warn};

/// Result of a fan-out request from a single provider
struct FanOutResult {
    provider: String,
    actual_model: String,
    response: ProviderResponse,
    latency_ms: u64,
}

/// Execute a fan-out request across multiple providers.
///
/// Dispatches the same request to N providers in parallel, then selects the
/// best response according to the configured mode.
pub async fn handle_fan_out(
    request: &AnthropicRequest,
    mappings: &[ModelMapping],
    fan_out_config: &FanOutConfig,
    registry: &Arc<ProviderRegistry>,
) -> Result<(ProviderResponse, Vec<(String, String)>), ProviderError> {
    let count = fan_out_config.count.unwrap_or(mappings.len()).min(mappings.len());
    let active_mappings = &mappings[..count];

    info!(
        "🔀 Fan-out: dispatching to {} providers (mode: {:?})",
        count,
        fan_out_config.mode
    );

    match fan_out_config.mode {
        FanOutMode::Fastest => fan_out_fastest(request, active_mappings, registry).await,
        FanOutMode::BestQuality => {
            fan_out_best_quality(request, active_mappings, fan_out_config, registry).await
        }
        FanOutMode::Weighted => fan_out_weighted(request, active_mappings, registry).await,
    }
}

/// Fastest mode: race all providers, return first success.
/// Other requests are dropped (cancelled) when the first one completes.
async fn fan_out_fastest(
    request: &AnthropicRequest,
    mappings: &[ModelMapping],
    registry: &Arc<ProviderRegistry>,
) -> Result<(ProviderResponse, Vec<(String, String)>), ProviderError> {
    use futures::future::select_all;

    let mut futures = Vec::new();
    let mut provider_info: Vec<(String, String)> = Vec::new();

    for mapping in mappings {
        let Some(provider) = registry.get_provider(&mapping.provider) else {
            continue;
        };
        let mut req = request.clone();
        req.model = mapping.actual_model.clone();
        let provider_name = mapping.provider.clone();
        let actual_model = mapping.actual_model.clone();
        provider_info.push((provider_name.clone(), actual_model.clone()));

        futures.push(Box::pin(async move {
            let start = std::time::Instant::now();
            let result = provider.send_message(req).await;
            let latency = start.elapsed().as_millis() as u64;
            (provider_name, actual_model, result, latency)
        }));
    }

    if futures.is_empty() {
        return Err(ProviderError::NoProviderAvailable);
    }

    // Race all futures, take first success
    let mut remaining = futures;
    while !remaining.is_empty() {
        let (result, _idx, rest) = select_all(remaining).await;
        let (provider_name, actual_model, response, latency) = result;

        match response {
            Ok(resp) => {
                info!(
                    "🏆 Fan-out fastest: {} ({}) won in {}ms",
                    provider_name, actual_model, latency
                );
                // Return all providers that were called for cost tracking
                return Ok((resp, provider_info));
            }
            Err(e) => {
                warn!(
                    "⚠️ Fan-out: {} ({}) failed: {}",
                    provider_name, actual_model, e
                );
                remaining = rest;
            }
        }
    }

    Err(ProviderError::AllProvidersFailed(
        "All fan-out providers failed".to_string(),
    ))
}

/// Best quality mode: wait for all responses, then use a judge model to pick the best.
async fn fan_out_best_quality(
    request: &AnthropicRequest,
    mappings: &[ModelMapping],
    fan_out_config: &FanOutConfig,
    registry: &Arc<ProviderRegistry>,
) -> Result<(ProviderResponse, Vec<(String, String)>), ProviderError> {
    let results = fan_out_all(request, mappings, registry).await;

    if results.is_empty() {
        return Err(ProviderError::AllProvidersFailed(
            "All fan-out providers failed".to_string(),
        ));
    }

    if results.len() == 1 {
        let r = results.into_iter().next().unwrap();
        let info = vec![(r.provider, r.actual_model)];
        return Ok((r.response, info));
    }

    // Build judge prompt
    let judge_model = fan_out_config
        .judge_model
        .as_deref()
        .unwrap_or("claude-haiku");
    let criteria = fan_out_config
        .judge_criteria
        .as_deref()
        .unwrap_or("Pick the most accurate, complete, and well-structured response");

    let mut judge_prompt = format!(
        "You are a response quality judge. Given {} candidate responses to the same prompt, \
         select the BEST one based on this criteria: {}\n\n\
         Reply with ONLY the number (1-{}) of the best response. Nothing else.\n\n",
        results.len(),
        criteria,
        results.len()
    );

    for (i, result) in results.iter().enumerate() {
        let text = extract_text_from_response(&result.response);
        judge_prompt.push_str(&format!("--- Response {} ---\n{}\n\n", i + 1, text));
    }

    // Send to judge model
    let provider_info: Vec<(String, String)> = results
        .iter()
        .map(|r| (r.provider.clone(), r.actual_model.clone()))
        .collect();

    if let Ok(judge_provider) = registry.get_provider_for_model(judge_model) {
        let judge_request = AnthropicRequest {
            model: judge_model.to_string(),
            messages: vec![crate::models::Message {
                role: "user".to_string(),
                content: crate::models::MessageContent::Text(judge_prompt),
            }],
            max_tokens: 10,
            stream: Some(false),
            ..request.clone()
        };

        match judge_provider.send_message(judge_request).await {
            Ok(judge_response) => {
                let judge_text = extract_text_from_response(&judge_response);
                let chosen_idx: usize = judge_text
                    .trim()
                    .chars()
                    .find(|c| c.is_ascii_digit())
                    .and_then(|c| c.to_digit(10))
                    .map(|d| d as usize)
                    .unwrap_or(1)
                    .saturating_sub(1)
                    .min(results.len() - 1);

                info!(
                    "🏆 Fan-out judge picked response {} from {} ({})",
                    chosen_idx + 1,
                    results[chosen_idx].provider,
                    results[chosen_idx].actual_model
                );

                let chosen = results.into_iter().nth(chosen_idx).unwrap();
                Ok((chosen.response, provider_info))
            }
            Err(e) => {
                warn!("⚠️ Judge model failed: {}, returning first response", e);
                let first = results.into_iter().next().unwrap();
                Ok((first.response, provider_info))
            }
        }
    } else {
        warn!(
            "⚠️ Judge model '{}' not found, returning first response",
            judge_model
        );
        let first = results.into_iter().next().unwrap();
        Ok((first.response, provider_info))
    }
}

/// Weighted mode: wait for all responses, score by latency/cost/length.
async fn fan_out_weighted(
    request: &AnthropicRequest,
    mappings: &[ModelMapping],
    registry: &Arc<ProviderRegistry>,
) -> Result<(ProviderResponse, Vec<(String, String)>), ProviderError> {
    let results = fan_out_all(request, mappings, registry).await;

    if results.is_empty() {
        return Err(ProviderError::AllProvidersFailed(
            "All fan-out providers failed".to_string(),
        ));
    }

    let provider_info: Vec<(String, String)> = results
        .iter()
        .map(|r| (r.provider.clone(), r.actual_model.clone()))
        .collect();

    // Score each response: lower latency is better, more output tokens is better
    let best = results
        .into_iter()
        .max_by(|a, b| {
            let score_a = weighted_score(a);
            let score_b = weighted_score(b);
            score_a
                .partial_cmp(&score_b)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .unwrap();

    info!(
        "🏆 Fan-out weighted: {} ({}) scored highest",
        best.provider, best.actual_model
    );

    Ok((best.response, provider_info))
}

fn weighted_score(result: &FanOutResult) -> f64 {
    let output_tokens = result.response.usage.output_tokens as f64;
    let latency_penalty = 1.0 / (1.0 + result.latency_ms as f64 / 1000.0);
    // More tokens * faster = higher score
    output_tokens * latency_penalty
}

/// Send request to all providers in parallel and collect successful results.
async fn fan_out_all(
    request: &AnthropicRequest,
    mappings: &[ModelMapping],
    registry: &Arc<ProviderRegistry>,
) -> Vec<FanOutResult> {
    use futures::future::join_all;

    let futures: Vec<_> = mappings
        .iter()
        .filter_map(|mapping| {
            let provider = registry.get_provider(&mapping.provider)?;
            let mut req = request.clone();
            req.model = mapping.actual_model.clone();
            let provider_name = mapping.provider.clone();
            let actual_model = mapping.actual_model.clone();

            Some(async move {
                let start = std::time::Instant::now();
                let result = provider.send_message(req).await;
                let latency = start.elapsed().as_millis() as u64;
                match result {
                    Ok(response) => {
                        info!(
                            "✅ Fan-out: {} ({}) responded in {}ms",
                            provider_name, actual_model, latency
                        );
                        Some(FanOutResult {
                            provider: provider_name,
                            actual_model,
                            response,
                            latency_ms: latency,
                        })
                    }
                    Err(e) => {
                        warn!("⚠️ Fan-out: {} ({}) failed: {}", provider_name, actual_model, e);
                        None
                    }
                }
            })
        })
        .collect();

    join_all(futures)
        .await
        .into_iter()
        .flatten()
        .collect()
}

/// Extract text content from an Anthropic response.
fn extract_text_from_response(response: &ProviderResponse) -> String {
    use crate::models::{ContentBlock, KnownContentBlock};
    response
        .content
        .iter()
        .filter_map(|block| {
            if let ContentBlock::Known(KnownContentBlock::Text { text, .. }) = block {
                Some(text.as_str())
            } else {
                None
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

//! Background bench engine: periodic tool-calling tests per (tool, provider).

pub mod evaluator;
pub mod test_cases;

use crate::features::mcp::config::BenchConfig;
use crate::features::mcp::matrix::{RuntimeScores, ToolMatrix, ToolScore};
use crate::features::mcp::scorer::ToolScorer;
use crate::models::{CanonicalRequest, Message, MessageContent};
use crate::providers::ProviderRegistry;

/// Max output tokens for bench requests.
///
/// Kept low (256) to minimize cost: bench only needs to observe tool_use blocks,
/// not full-length completions.
const BENCH_MAX_TOKENS: u32 = 256;

/// Temperature for bench requests.
///
/// Set to 0.0 for deterministic output so scores are reproducible across cycles.
const BENCH_TEMPERATURE: f32 = 0.0;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Spawns the background bench engine as a tokio task.
///
/// Runs a bench cycle at the configured interval, testing tool-calling
/// capabilities across all tools and providers in the matrix.
pub fn spawn_bench_engine(
    config: BenchConfig,
    matrix: &ToolMatrix,
    scorer: Arc<RwLock<ToolScorer>>,
    runtime_scores: RuntimeScores,
    registry: Arc<ProviderRegistry>,
) {
    let entries: Vec<_> = matrix.all_entries().to_vec();
    let concurrency = config.concurrency;
    let timeout_ms = config.timeout_ms;
    let interval_secs = config.interval_secs;

    info!(
        interval_secs,
        concurrency, "Starting MCP bench engine background task"
    );

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));

        loop {
            interval.tick().await;
            debug!(phase = "start", "MCP bench cycle");

            run_bench_cycle(
                &entries,
                &scorer,
                &runtime_scores,
                &registry,
                concurrency,
                timeout_ms,
            )
            .await;

            debug!(phase = "complete", "MCP bench cycle");
        }
    });
}

/// Runs a single bench cycle: iterates tools x providers x test_cases.
async fn run_bench_cycle(
    entries: &[crate::features::mcp::matrix::ToolEntry],
    scorer: &Arc<RwLock<ToolScorer>>,
    runtime_scores: &RuntimeScores,
    registry: &Arc<ProviderRegistry>,
    concurrency: usize,
    timeout_ms: u64,
) {
    let test_cases = Arc::new(test_cases::all_test_cases());
    let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));
    let mut handles = Vec::new();

    for entry in entries {
        for provider_name in entry.providers.keys() {
            let provider = match registry.provider(provider_name) {
                Some(p) => p,
                None => {
                    debug!(provider = %provider_name, "Provider not found in registry, skipping");
                    continue;
                }
            };

            for test_case_idx in 0..test_cases.len() {
                let sem = semaphore.clone();
                let provider = provider.clone();
                let provider_name = provider_name.clone();
                let tool_name = entry.name.clone();
                let scorer = scorer.clone();
                let runtime_scores = runtime_scores.clone();
                let timeout = std::time::Duration::from_millis(timeout_ms);
                let test_cases = test_cases.clone();

                let handle = tokio::spawn(async move {
                    let _permit = sem.acquire().await;
                    let test_case = &test_cases[test_case_idx];

                    // Build request
                    let messages = if test_case.metric
                        == crate::features::mcp::scorer::ToolMetric::ToolResultHandling
                    {
                        test_cases::tool_result_messages()
                    } else {
                        vec![Message {
                            role: "user".to_string(),
                            content: MessageContent::Text(test_case.user_message.to_string()),
                        }]
                    };

                    let tool_choice = test_case
                        .forced_tool
                        .map(|name| serde_json::json!({"type": "tool", "name": name}));

                    let request = CanonicalRequest {
                        model: String::new(), // Provider will use its default
                        messages,
                        max_tokens: BENCH_MAX_TOKENS,
                        thinking: None,
                        temperature: Some(BENCH_TEMPERATURE),
                        top_p: None,
                        top_k: None,
                        stop_sequences: None,
                        stream: Some(false),
                        metadata: None,
                        system: Some(crate::models::SystemPrompt::Text(
                            test_case.system_prompt.to_string(),
                        )),
                        tools: Some(test_case.tools.clone()),
                        tool_choice,
                        extensions: Default::default(),
                    };

                    // Send request with timeout
                    let result =
                        tokio::time::timeout(timeout, provider.send_message(request)).await;

                    match result {
                        Ok(Ok(response)) => {
                            let eval = evaluator::evaluate(test_case, &response);
                            debug!(
                                tool = %tool_name,
                                provider = %provider_name,
                                metric = ?eval.metric,
                                success = eval.success,
                                detail = %eval.detail,
                                "Bench eval"
                            );

                            // Record the metric
                            let mut s = scorer.write().await;
                            s.record(&tool_name, &provider_name, eval.metric, eval.success);
                            let composite = s.composite_score(&tool_name, &provider_name, None);
                            let metrics = s.metric_breakdown(&tool_name, &provider_name);
                            drop(s);

                            // Update runtime scores
                            let score = ToolScore {
                                composite,
                                last_bench_epoch: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs(),
                                metrics,
                            };
                            runtime_scores.insert(tool_name, provider_name, score).await;
                        }
                        Ok(Err(e)) => {
                            warn!(
                                tool = %tool_name,
                                provider = %provider_name,
                                error = %e,
                                "Bench request failed"
                            );
                            let mut s = scorer.write().await;
                            s.record(&tool_name, &provider_name, test_case.metric, false);
                        }
                        Err(_) => {
                            warn!(
                                tool = %tool_name,
                                provider = %provider_name,
                                "Bench request timed out"
                            );
                            let mut s = scorer.write().await;
                            s.record(&tool_name, &provider_name, test_case.metric, false);
                        }
                    }
                });

                handles.push(handle);
            }
        }
    }

    // Await all bench tasks
    for handle in handles {
        if let Err(e) = handle.await {
            warn!(error = %e, "Bench task panicked");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_test_cases_not_empty() {
        let cases = test_cases::all_test_cases();
        assert!(!cases.is_empty());
    }
}

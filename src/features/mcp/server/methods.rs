//! MCP JSON-RPC method implementations: query, bench, calibrate, report, tools/list.
//!
//! Pure business logic with no dependency on `server::AppState`. The
//! self-tuning `grob_configure` handler lives in `server::mcp_handlers`
//! because it needs `AppState` for hot-reload.

use super::types::*;
use crate::features::mcp::McpState;
use std::collections::HashMap;

/// Sentinel epoch for tools that have never been benchmarked.
const NO_BENCH_EPOCH: u64 = 0;

/// Handles `tool_matrix/query` — returns scores for a tool, optionally filtered by provider.
pub async fn handle_query(
    mcp: &McpState,
    params: serde_json::Value,
    id: serde_json::Value,
) -> Result<JsonRpcResponse, JsonRpcError> {
    let p: QueryParams = serde_json::from_value(params)
        .map_err(|e| JsonRpcError::invalid_params(id.clone(), &e.to_string()))?;

    let entry = mcp.matrix.query(&p.tool).ok_or_else(|| {
        JsonRpcError::invalid_params(id.clone(), &format!("Unknown tool: {}", p.tool))
    })?;

    let scorer = mcp.read_scorer().await;
    let runtime_scores = mcp.matrix.scores_handle();

    let mut providers: HashMap<String, serde_json::Value> = HashMap::new();
    for (prov, cap) in entry
        .providers
        .iter()
        .filter(|(prov, _)| p.provider.as_ref().is_none_or(|f| f == *prov))
    {
        let composite = scorer.composite_score(&p.tool, prov, Some(cap.reliability));
        let metrics = scorer.metric_breakdown(&p.tool, prov);
        let last_bench = runtime_scores
            .get(&p.tool, prov)
            .await
            .map(|s| s.last_bench_epoch)
            .unwrap_or(NO_BENCH_EPOCH);

        providers.insert(
            prov.clone(),
            serde_json::json!({
                "static_reliability": cap.reliability,
                "composite": composite,
                "last_bench_epoch": last_bench,
                "metrics": metrics,
            }),
        );
    }

    Ok(JsonRpcResponse::ok(
        id,
        serde_json::json!({
            "tool": p.tool,
            "category": entry.category,
            "aliases": entry.aliases,
            "providers": providers,
        }),
    ))
}

/// Handles `tool_matrix/bench` — triggers an on-demand bench cycle (placeholder).
pub async fn handle_bench(
    _mcp: &McpState,
    params: serde_json::Value,
    id: serde_json::Value,
) -> Result<JsonRpcResponse, JsonRpcError> {
    let p: BenchParams = serde_json::from_value(params)
        .map_err(|e| JsonRpcError::invalid_params(id.clone(), &e.to_string()))?;

    // NOTE: actual bench dispatch is handled by the bench engine;
    // here we acknowledge the request.
    Ok(JsonRpcResponse::ok(
        id,
        serde_json::json!({
            "status": "accepted",
            "tools": p.tools.unwrap_or_default(),
            "providers": p.providers.unwrap_or_default(),
        }),
    ))
}

/// Handles `tool_matrix/calibrate` — manual score override.
pub async fn handle_calibrate(
    mcp: &McpState,
    params: serde_json::Value,
    id: serde_json::Value,
) -> Result<JsonRpcResponse, JsonRpcError> {
    let p: CalibrateParams = serde_json::from_value(params)
        .map_err(|e| JsonRpcError::invalid_params(id.clone(), &e.to_string()))?;

    if !(0.0..=1.0).contains(&p.score) {
        return Err(JsonRpcError::invalid_params(
            id,
            "score must be between 0.0 and 1.0",
        ));
    }

    mcp.matrix
        .update_score(&p.tool, &p.provider, p.score, HashMap::new())
        .await;

    tracing::info!(
        tool = %p.tool,
        provider = %p.provider,
        score = p.score,
        "MCP: manual calibration override"
    );

    Ok(JsonRpcResponse::ok(
        id,
        serde_json::json!({
            "tool": p.tool,
            "provider": p.provider,
            "score": p.score,
        }),
    ))
}

/// Handles `tool_matrix/report` — returns the full matrix with all scores.
pub async fn handle_report(
    mcp: &McpState,
    id: serde_json::Value,
) -> Result<JsonRpcResponse, JsonRpcError> {
    let report = build_matrix_report(mcp).await;
    Ok(JsonRpcResponse::ok(id, report))
}

/// Handles `tools/list` — MCP standard tool listing.
pub async fn handle_tools_list(
    mcp: &McpState,
    id: serde_json::Value,
) -> Result<JsonRpcResponse, JsonRpcError> {
    let tools: Vec<McpToolInfo> = mcp
        .matrix
        .all_entries()
        .iter()
        .map(|entry| {
            let schema = serde_json::json!({
                "type": entry.schema.r#type,
                "properties": entry.schema.properties,
                "required": entry.schema.required,
            });
            McpToolInfo {
                name: entry.name.clone(),
                description: format!("{} tool (category: {})", entry.name, entry.category),
                input_schema: schema,
            }
        })
        .collect();

    Ok(JsonRpcResponse::ok(
        id,
        serde_json::json!({ "tools": tools }),
    ))
}

/// Builds the full matrix report (reused by both JSON-RPC and REST endpoints).
pub async fn build_matrix_report(mcp: &McpState) -> serde_json::Value {
    let scorer = mcp.read_scorer().await;
    let runtime_scores = mcp.matrix.scores_handle();

    let mut tools: Vec<serde_json::Value> = Vec::new();
    for entry in mcp.matrix.all_entries() {
        let mut providers: HashMap<String, serde_json::Value> = HashMap::new();
        for (prov, cap) in &entry.providers {
            let composite = scorer.composite_score(&entry.name, prov, Some(cap.reliability));
            let metrics = scorer.metric_breakdown(&entry.name, prov);
            let last_bench = runtime_scores
                .get(&entry.name, prov)
                .await
                .map(|s| s.last_bench_epoch)
                .unwrap_or(NO_BENCH_EPOCH);

            providers.insert(
                prov.clone(),
                serde_json::json!({
                    "static_reliability": cap.reliability,
                    "composite": composite,
                    "last_bench_epoch": last_bench,
                    "metrics": metrics,
                }),
            );
        }

        tools.push(serde_json::json!({
            "name": entry.name,
            "aliases": entry.aliases,
            "category": entry.category,
            "providers": providers,
        }));
    }

    serde_json::json!({
        "tool_count": mcp.matrix.tool_count(),
        "tools": tools,
        "config": {
            "filter_low_score_tools": mcp.config.routing.filter_low_score_tools,
            "min_score": mcp.config.routing.min_score,
            "bench_enabled": mcp.config.bench.enabled,
            "bench_interval_secs": mcp.config.bench.interval_secs,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::mcp::config::McpConfig;
    use crate::features::mcp::matrix::{ProviderToolCapability, ToolEntry, ToolMatrix, ToolSchema};

    fn test_mcp_state() -> McpState {
        let entries = vec![ToolEntry {
            name: "web_search".to_string(),
            aliases: vec!["brave_search".to_string()],
            category: "retrieval".to_string(),
            schema: ToolSchema {
                r#type: "object".to_string(),
                properties: HashMap::from([(
                    "query".to_string(),
                    serde_json::json!({"type": "string"}),
                )]),
                required: vec!["query".to_string()],
            },
            providers: HashMap::from([(
                "anthropic".to_string(),
                ProviderToolCapability { reliability: 0.95 },
            )]),
        }];

        McpState::new(McpConfig::default(), ToolMatrix::from_entries(entries))
    }

    #[tokio::test]
    async fn test_handle_query() {
        let mcp = test_mcp_state();
        let params = serde_json::json!({"tool": "web_search"});
        let result = handle_query(&mcp, params, serde_json::json!(1))
            .await
            .unwrap();
        assert!(
            result.result["providers"]["anthropic"]["static_reliability"]
                .as_f64()
                .unwrap()
                > 0.9
        );
    }

    #[tokio::test]
    async fn test_handle_query_unknown_tool() {
        let mcp = test_mcp_state();
        let params = serde_json::json!({"tool": "nonexistent"});
        let err = handle_query(&mcp, params, serde_json::json!(1))
            .await
            .unwrap_err();
        assert_eq!(err.error.code, -32602);
    }

    #[tokio::test]
    async fn test_handle_calibrate() {
        let mcp = test_mcp_state();
        let params =
            serde_json::json!({"tool": "web_search", "provider": "anthropic", "score": 0.8});
        let result = handle_calibrate(&mcp, params, serde_json::json!(1))
            .await
            .unwrap();
        assert!((result.result["score"].as_f64().unwrap() - 0.8).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_handle_calibrate_invalid_score() {
        let mcp = test_mcp_state();
        let params =
            serde_json::json!({"tool": "web_search", "provider": "anthropic", "score": 1.5});
        let err = handle_calibrate(&mcp, params, serde_json::json!(1))
            .await
            .unwrap_err();
        assert_eq!(err.error.code, -32602);
    }

    #[tokio::test]
    async fn test_handle_report() {
        let mcp = test_mcp_state();
        let result = handle_report(&mcp, serde_json::json!(1)).await.unwrap();
        assert_eq!(result.result["tool_count"], 1);
    }

    #[tokio::test]
    async fn test_handle_tools_list() {
        let mcp = test_mcp_state();
        let result = handle_tools_list(&mcp, serde_json::json!(1)).await.unwrap();
        let tools = result.result["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "web_search");
    }
}

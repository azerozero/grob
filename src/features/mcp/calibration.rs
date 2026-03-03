//! Tool calibration in the dispatch pipeline.
//!
//! Filters unreliable tools from requests before they reach the provider,
//! based on the tool matrix scores and routing configuration.

use super::McpState;
use crate::models::AnthropicRequest;

/// Score assigned to tools not found in the matrix.
///
/// Unknown tools are treated as maximally unreliable so they are filtered
/// out when `filter_low_score_tools` is enabled.
const UNKNOWN_TOOL_SCORE: f64 = 0.0;

/// Filters tools whose max static score falls below the threshold.
///
/// Called between DLP scanning (Step 1) and cache lookup (Step 2) in the
/// dispatch pipeline. Only active when `routing.filter_low_score_tools` is
/// enabled in the MCP config. Uses static scores only to avoid async overhead
/// on the hot path.
pub fn calibrate_tools(mcp: &McpState, request: &mut AnthropicRequest) {
    if !mcp.config.routing.filter_low_score_tools {
        return;
    }

    let tools = match request.tools.as_mut() {
        Some(t) if !t.is_empty() => t,
        _ => return,
    };

    let min_score = mcp.config.routing.min_score;
    let original_len = tools.len();

    tools.retain(|tool| {
        let tool_name = match tool.name.as_deref() {
            Some(n) => n,
            None => return true, // Keep tools without a name (cannot look up)
        };

        // Check per-tool chain override first
        let threshold = mcp
            .config
            .routing
            .chains
            .iter()
            .find(|c| c.tool == tool_name)
            .map(|c| c.min_score)
            .unwrap_or(min_score);

        // Synchronous check: use static score only (avoids async in retain)
        let score = mcp
            .matrix
            .query(tool_name)
            .and_then(|entry| {
                entry
                    .providers
                    .values()
                    .map(|cap| cap.reliability)
                    .reduce(f64::max)
            })
            .unwrap_or(UNKNOWN_TOOL_SCORE);

        score >= threshold
    });

    let removed_count = original_len - tools.len();
    if removed_count > 0 {
        tracing::debug!(
            removed_count,
            min_score,
            "MCP calibration: removed unreliable tools"
        );
    }

    // Clear tools if all were removed
    if tools.is_empty() {
        request.tools = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::mcp::config::{McpConfig, ToolRoutingConfig};
    use crate::features::mcp::matrix::{ProviderToolCapability, ToolEntry, ToolMatrix, ToolSchema};
    use crate::models::Tool;
    use std::collections::HashMap;

    fn test_mcp_state(min_score: f64) -> McpState {
        let entries = vec![
            ToolEntry {
                name: "good_tool".to_string(),
                aliases: vec![],
                category: "test".to_string(),
                schema: ToolSchema::default(),
                providers: HashMap::from([(
                    "anthropic".to_string(),
                    ProviderToolCapability { reliability: 0.9 },
                )]),
            },
            ToolEntry {
                name: "bad_tool".to_string(),
                aliases: vec![],
                category: "test".to_string(),
                schema: ToolSchema::default(),
                providers: HashMap::from([(
                    "anthropic".to_string(),
                    ProviderToolCapability { reliability: 0.2 },
                )]),
            },
        ];

        let config = McpConfig {
            enabled: true,
            routing: ToolRoutingConfig {
                min_score,
                filter_low_score_tools: true,
                chains: vec![],
            },
            ..McpConfig::default()
        };

        McpState::new(config, ToolMatrix::from_entries(entries))
    }

    fn make_request(tool_names: &[&str]) -> AnthropicRequest {
        let tools: Vec<Tool> = tool_names
            .iter()
            .map(|name| Tool {
                r#type: Some("custom".to_string()),
                name: Some(name.to_string()),
                description: None,
                input_schema: None,
            })
            .collect();

        AnthropicRequest {
            model: "test".to_string(),
            messages: vec![],
            max_tokens: 1024,
            thinking: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop_sequences: None,
            stream: None,
            metadata: None,
            system: None,
            tools: Some(tools),
            tool_choice: None,
        }
    }

    #[test]
    fn test_filters_low_score_tools() {
        let mcp = test_mcp_state(0.5);
        let mut request = make_request(&["good_tool", "bad_tool"]);

        calibrate_tools(&mcp, &mut request);

        let remaining: Vec<_> = request
            .tools
            .as_ref()
            .unwrap()
            .iter()
            .filter_map(|t| t.name.as_deref())
            .collect();
        assert_eq!(remaining, vec!["good_tool"]);
    }

    #[test]
    fn test_keeps_all_tools_above_threshold() {
        let mcp = test_mcp_state(0.1);
        let mut request = make_request(&["good_tool", "bad_tool"]);

        calibrate_tools(&mcp, &mut request);

        assert_eq!(request.tools.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn test_clears_tools_when_all_removed() {
        let mcp = test_mcp_state(0.95);
        let mut request = make_request(&["bad_tool"]);

        calibrate_tools(&mcp, &mut request);

        assert!(request.tools.is_none());
    }

    #[test]
    fn test_noop_when_disabled() {
        let mut mcp = test_mcp_state(0.5);
        mcp.config.routing.filter_low_score_tools = false;
        let mut request = make_request(&["bad_tool"]);

        calibrate_tools(&mcp, &mut request);

        assert_eq!(request.tools.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn test_noop_when_no_tools() {
        let mcp = test_mcp_state(0.5);
        let mut request = make_request(&[]);
        request.tools = None;

        calibrate_tools(&mcp, &mut request);

        assert!(request.tools.is_none());
    }

    #[test]
    fn test_unknown_tool_removed() {
        let mcp = test_mcp_state(0.5);
        let mut request = make_request(&["unknown_tool"]);

        calibrate_tools(&mcp, &mut request);

        // Unknown tool has score 0.0 < 0.5, so it gets removed
        assert!(request.tools.is_none());
    }
}

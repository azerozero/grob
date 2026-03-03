//! Bench test case fixtures for the 6 tool-calling metrics.

use crate::features::mcp::scorer::ToolMetric;
use crate::models::{ContentBlock, Message, MessageContent, Tool};

/// JSON Schema for a single-string query tool (web_search).
const SEARCH_SCHEMA: &str =
    r#"{"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}"#;

/// JSON Schema for a single-string expression tool (calculator).
const CALCULATOR_SCHEMA: &str =
    r#"{"type":"object","properties":{"expression":{"type":"string"}},"required":["expression"]}"#;

/// JSON Schema for the weather tool (city required, unit optional).
const WEATHER_SCHEMA: &str = r#"{"type":"object","properties":{"city":{"type":"string"},"unit":{"type":"string","enum":["celsius","fahrenheit"]}},"required":["city"]}"#;

/// A single bench test case.
#[derive(Debug)]
pub struct BenchTestCase {
    /// Which metric this test evaluates.
    pub metric: ToolMetric,
    /// System prompt (minimal, <50 tokens).
    pub system_prompt: &'static str,
    /// User message.
    pub user_message: &'static str,
    /// Tools to provide in the request.
    pub tools: Vec<Tool>,
    /// If set, force `tool_choice` to this tool name.
    pub forced_tool: Option<&'static str>,
    /// Expected tool name(s) in the response.
    pub expected_tools: Vec<&'static str>,
    /// Whether the test expects parallel tool calls.
    pub expect_parallel: bool,
}

/// Returns the full set of bench test cases.
pub fn all_test_cases() -> Vec<BenchTestCase> {
    vec![
        // ── tool_selection_accuracy ──
        BenchTestCase {
            metric: ToolMetric::ToolSelectionAccuracy,
            system_prompt: "You are a helpful assistant with tool access.",
            user_message: "Search the web for 'rust programming'",
            tools: vec![
                make_tool("web_search", "Search the web", SEARCH_SCHEMA),
                make_tool("calculator", "Perform math", CALCULATOR_SCHEMA),
            ],
            forced_tool: None,
            expected_tools: vec!["web_search"],
            expect_parallel: false,
        },
        // ── param_validity ──
        BenchTestCase {
            metric: ToolMetric::ParamValidity,
            system_prompt: "You are a helpful assistant with tool access.",
            user_message: "Calculate 2 + 2",
            tools: vec![make_tool("calculator", "Perform math", CALCULATOR_SCHEMA)],
            forced_tool: None,
            expected_tools: vec!["calculator"],
            expect_parallel: false,
        },
        // ── param_compliance ──
        BenchTestCase {
            metric: ToolMetric::ParamCompliance,
            system_prompt: "You are a helpful assistant with tool access.",
            user_message: "Look up the weather in Paris",
            tools: vec![make_tool("weather", "Get weather", WEATHER_SCHEMA)],
            forced_tool: None,
            expected_tools: vec!["weather"],
            expect_parallel: false,
        },
        // ── tool_choice_respect ──
        BenchTestCase {
            metric: ToolMetric::ToolChoiceRespect,
            system_prompt: "You are a helpful assistant with tool access.",
            user_message: "Tell me about Rust",
            tools: vec![
                make_tool("web_search", "Search the web", SEARCH_SCHEMA),
                make_tool("calculator", "Perform math", CALCULATOR_SCHEMA),
            ],
            forced_tool: Some("web_search"),
            expected_tools: vec!["web_search"],
            expect_parallel: false,
        },
        // ── parallel_tool_support ──
        BenchTestCase {
            metric: ToolMetric::ParallelToolSupport,
            system_prompt: "You are a helpful assistant. Use both tools in a single response.",
            user_message: "Search for 'Rust language' and calculate 7 * 8",
            tools: vec![
                make_tool("web_search", "Search the web", SEARCH_SCHEMA),
                make_tool("calculator", "Perform math", CALCULATOR_SCHEMA),
            ],
            forced_tool: None,
            expected_tools: vec!["web_search", "calculator"],
            expect_parallel: true,
        },
        // ── tool_result_handling ──
        BenchTestCase {
            metric: ToolMetric::ToolResultHandling,
            system_prompt: "You are a helpful assistant with tool access.",
            user_message: "What is 15 * 23?",
            tools: vec![make_tool("calculator", "Perform math", CALCULATOR_SCHEMA)],
            forced_tool: None,
            expected_tools: vec!["calculator"],
            expect_parallel: false,
        },
    ]
}

/// Builds a pre-filled conversation for tool_result_handling tests.
///
/// Contains: user message → assistant tool_use → user tool_result.
/// The bench evaluator checks that the model continues correctly after the tool_result.
pub fn tool_result_messages() -> Vec<Message> {
    vec![
        Message {
            role: "user".to_string(),
            content: MessageContent::Text("What is 15 * 23?".to_string()),
        },
        Message {
            role: "assistant".to_string(),
            content: MessageContent::Blocks(vec![ContentBlock::Unknown(serde_json::json!({
                "type": "tool_use",
                "id": "bench_tu_1",
                "name": "calculator",
                "input": {"expression": "15 * 23"}
            }))]),
        },
        Message {
            role: "user".to_string(),
            content: MessageContent::Blocks(vec![ContentBlock::Unknown(serde_json::json!({
                "type": "tool_result",
                "tool_use_id": "bench_tu_1",
                "content": "345"
            }))]),
        },
    ]
}

fn make_tool(name: &str, description: &str, schema_json: &str) -> Tool {
    Tool {
        r#type: Some("custom".to_string()),
        name: Some(name.to_string()),
        description: Some(description.to_string()),
        // Schema literals are hardcoded valid JSON; a parse failure here
        // indicates a programming bug in the test fixtures.
        input_schema: Some(
            serde_json::from_str(schema_json).expect("bench fixture: invalid JSON schema literal"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_test_cases_cover_all_metrics() {
        let cases = all_test_cases();
        for metric in ToolMetric::all() {
            assert!(
                cases.iter().any(|c| c.metric == *metric),
                "Missing test case for metric: {:?}",
                metric
            );
        }
    }

    #[test]
    fn test_tool_result_messages_structure() {
        let msgs = tool_result_messages();
        assert_eq!(msgs.len(), 3);
        assert_eq!(msgs[0].role, "user");
        assert_eq!(msgs[1].role, "assistant");
        assert_eq!(msgs[2].role, "user");
    }
}

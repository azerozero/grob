//! Bench result evaluator: scores provider responses against test case expectations.

use crate::features::mcp::bench::test_cases::BenchTestCase;
use crate::features::mcp::scorer::ToolMetric;
use crate::models::{ContentBlock, KnownContentBlock};
use crate::providers::ProviderResponse;

/// Result of evaluating a single bench test case.
#[derive(Debug)]
pub struct EvalResult {
    /// Metric evaluated by this test.
    pub metric: ToolMetric,
    /// Whether the evaluation passed.
    pub success: bool,
    /// Human-readable explanation of the result.
    pub detail: String,
}

impl std::fmt::Display for EvalResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: {} ({})",
            self.metric,
            if self.success { "pass" } else { "fail" },
            self.detail
        )
    }
}

/// Evaluates a provider response against a bench test case.
pub fn evaluate(test_case: &BenchTestCase, response: &ProviderResponse) -> EvalResult {
    match test_case.metric {
        ToolMetric::ToolSelectionAccuracy => eval_tool_selection(test_case, response),
        ToolMetric::ParamValidity => eval_param_validity(response),
        ToolMetric::ParamCompliance => eval_param_compliance(test_case, response),
        ToolMetric::ToolChoiceRespect => eval_tool_choice_respect(test_case, response),
        ToolMetric::ParallelToolSupport => eval_parallel_support(test_case, response),
        ToolMetric::ToolResultHandling => eval_tool_result_handling(response),
    }
}

/// Checks that the model selected one of the expected tools.
fn eval_tool_selection(test_case: &BenchTestCase, response: &ProviderResponse) -> EvalResult {
    let tool_names = extract_tool_use_names(&response.content);

    let success = test_case
        .expected_tools
        .iter()
        .any(|expected| tool_names.iter().any(|name| name == expected));

    EvalResult {
        metric: ToolMetric::ToolSelectionAccuracy,
        success,
        detail: format!(
            "expected {:?}, got {:?}",
            test_case.expected_tools, tool_names
        ),
    }
}

/// Checks that tool_use blocks have valid JSON `input`.
fn eval_param_validity(response: &ProviderResponse) -> EvalResult {
    let tool_uses = extract_tool_use_blocks(&response.content);

    if tool_uses.is_empty() {
        return EvalResult {
            metric: ToolMetric::ParamValidity,
            success: false,
            detail: "no tool_use blocks found".to_string(),
        };
    }

    let all_valid = tool_uses.iter().all(|tu| {
        tu.get("input")
            .map(|v| v.is_object() || v.is_array())
            .unwrap_or(false)
    });

    EvalResult {
        metric: ToolMetric::ParamValidity,
        success: all_valid,
        detail: format!(
            "{} tool_use blocks, all_valid={}",
            tool_uses.len(),
            all_valid
        ),
    }
}

/// Checks that required fields are present in tool_use `input`.
fn eval_param_compliance(test_case: &BenchTestCase, response: &ProviderResponse) -> EvalResult {
    let tool_uses = extract_tool_use_blocks(&response.content);

    if tool_uses.is_empty() {
        return EvalResult {
            metric: ToolMetric::ParamCompliance,
            success: false,
            detail: "no tool_use blocks found".to_string(),
        };
    }

    // Check the first matching tool's required fields
    let expected_tool = test_case.expected_tools.first().copied().unwrap_or("");
    let matching_tool = tool_uses
        .iter()
        .find(|tu| tu.get("name").and_then(|n| n.as_str()) == Some(expected_tool));

    let success = match matching_tool {
        Some(tu) => {
            let input = tu.get("input").and_then(|v| v.as_object());
            match (&test_case.tools.first(), input) {
                (Some(tool_def), Some(input_obj)) => {
                    // Extract required fields from schema
                    let required: Vec<String> = tool_def
                        .input_schema
                        .as_ref()
                        .and_then(|s| s.get("required"))
                        .and_then(|r| r.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                .collect()
                        })
                        .unwrap_or_default();

                    required.iter().all(|field| input_obj.contains_key(field))
                }
                _ => false,
            }
        }
        None => false,
    };

    EvalResult {
        metric: ToolMetric::ParamCompliance,
        success,
        detail: format!("expected tool '{}', compliance={}", expected_tool, success),
    }
}

/// Checks that the model respected `tool_choice` forcing.
fn eval_tool_choice_respect(test_case: &BenchTestCase, response: &ProviderResponse) -> EvalResult {
    let forced = match test_case.forced_tool {
        Some(name) => name,
        None => {
            return EvalResult {
                metric: ToolMetric::ToolChoiceRespect,
                success: true,
                detail: "no forced tool".to_string(),
            }
        }
    };

    let tool_names = extract_tool_use_names(&response.content);
    let success = tool_names.iter().any(|name| name == forced);

    EvalResult {
        metric: ToolMetric::ToolChoiceRespect,
        success,
        detail: format!("forced '{}', got {:?}", forced, tool_names),
    }
}

/// Checks that the model emitted multiple tool_use blocks.
fn eval_parallel_support(test_case: &BenchTestCase, response: &ProviderResponse) -> EvalResult {
    let tool_names = extract_tool_use_names(&response.content);

    let success = if test_case.expect_parallel {
        tool_names.len() >= 2
    } else {
        !tool_names.is_empty()
    };

    EvalResult {
        metric: ToolMetric::ParallelToolSupport,
        success,
        detail: format!(
            "expected parallel={}, got {} tool calls",
            test_case.expect_parallel,
            tool_names.len()
        ),
    }
}

/// Checks that the model produced a text continuation after a tool_result.
fn eval_tool_result_handling(response: &ProviderResponse) -> EvalResult {
    let has_text = response.content.iter().any(|block| match block {
        ContentBlock::Known(KnownContentBlock::Text { text, .. }) => !text.trim().is_empty(),
        _ => false,
    });

    EvalResult {
        metric: ToolMetric::ToolResultHandling,
        success: has_text,
        detail: format!("has_text_continuation={}", has_text),
    }
}

/// Extracts tool names from tool_use content blocks.
fn extract_tool_use_names(content: &[ContentBlock]) -> Vec<String> {
    extract_tool_use_blocks(content)
        .iter()
        .filter_map(|tu| tu.get("name").and_then(|n| n.as_str()).map(String::from))
        .collect()
}

/// Extracts raw tool_use JSON objects from content blocks.
fn extract_tool_use_blocks(content: &[ContentBlock]) -> Vec<&serde_json::Value> {
    content
        .iter()
        .filter_map(|block| match block {
            ContentBlock::Unknown(val) => {
                if val.get("type").and_then(|t| t.as_str()) == Some("tool_use") {
                    Some(val)
                } else {
                    None
                }
            }
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::Usage;

    fn test_usage() -> Usage {
        Usage {
            input_tokens: 10,
            output_tokens: 5,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        }
    }

    fn make_tool_use_response(tool_uses: Vec<serde_json::Value>) -> ProviderResponse {
        let content = tool_uses.into_iter().map(ContentBlock::Unknown).collect();
        ProviderResponse {
            id: "test".to_string(),
            r#type: "message".to_string(),
            role: "assistant".to_string(),
            content,
            model: "test".to_string(),
            stop_reason: Some("tool_use".to_string()),
            stop_sequence: None,
            usage: test_usage(),
        }
    }

    fn make_text_response(text: &str) -> ProviderResponse {
        ProviderResponse {
            id: "test".to_string(),
            r#type: "message".to_string(),
            role: "assistant".to_string(),
            content: vec![ContentBlock::text(text.to_string(), None)],
            model: "test".to_string(),
            stop_reason: Some("end_turn".to_string()),
            stop_sequence: None,
            usage: test_usage(),
        }
    }

    #[test]
    fn test_eval_tool_selection_success() {
        let response = make_tool_use_response(vec![serde_json::json!({
            "type": "tool_use",
            "id": "tu_1",
            "name": "web_search",
            "input": {"query": "rust"}
        })]);

        let test_case = &super::super::test_cases::all_test_cases()[0];
        let result = eval_tool_selection(test_case, &response);
        assert!(result.success);
    }

    #[test]
    fn test_eval_param_validity_success() {
        let response = make_tool_use_response(vec![serde_json::json!({
            "type": "tool_use",
            "id": "tu_1",
            "name": "calculator",
            "input": {"expression": "2+2"}
        })]);

        let result = eval_param_validity(&response);
        assert!(result.success);
    }

    #[test]
    fn test_eval_param_validity_no_tool_use() {
        let response = make_text_response("Just text");
        let result = eval_param_validity(&response);
        assert!(!result.success);
    }

    #[test]
    fn test_eval_parallel_support() {
        let response = make_tool_use_response(vec![
            serde_json::json!({
                "type": "tool_use", "id": "tu_1", "name": "web_search", "input": {"query": "rust"}
            }),
            serde_json::json!({
                "type": "tool_use", "id": "tu_2", "name": "calculator", "input": {"expression": "7*8"}
            }),
        ]);

        let test_case = &super::super::test_cases::all_test_cases()[4]; // parallel test
        let result = eval_parallel_support(test_case, &response);
        assert!(result.success);
    }

    #[test]
    fn test_eval_tool_result_handling_has_text() {
        let response = make_text_response("The result of 15 * 23 is 345.");
        let result = eval_tool_result_handling(&response);
        assert!(result.success);
    }

    #[test]
    fn test_eval_tool_result_handling_empty() {
        let response = make_text_response("");
        let result = eval_tool_result_handling(&response);
        assert!(!result.success);
    }
}

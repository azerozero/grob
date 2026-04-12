//! Bidirectional transformation between Responses API and canonical format.

use crate::models::{
    self, CanonicalRequest, ContentBlock, KnownContentBlock, Message, MessageContent, SystemPrompt,
    Tool, ToolResultContent,
};
use crate::providers::ProviderResponse;

use super::types::*;

/// Extracts text from [`InputContent`].
fn extract_input_text(content: &InputContent) -> String {
    match content {
        InputContent::Text(s) => s.clone(),
        InputContent::Parts(parts) => parts
            .iter()
            .map(|p| match p {
                InputContentPart::InputText { text } => text.as_str(),
            })
            .collect::<Vec<_>>()
            .join("\n"),
    }
}

/// Converts Responses API tools (flat format) to canonical [`Tool`] format.
fn convert_tools(tools: &[serde_json::Value]) -> Vec<Tool> {
    tools
        .iter()
        .filter_map(|t| {
            let name = t
                .get("name")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            // Responses API uses flat format: { type, name, description, parameters }
            // (no nested "function" wrapper like Chat Completions)
            if name.is_some() {
                Some(Tool {
                    r#type: None,
                    name,
                    description: t
                        .get("description")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    input_schema: t.get("parameters").cloned(),
                })
            } else {
                // Fallback: try Chat Completions nested format
                let func = t.get("function")?;
                Some(Tool {
                    r#type: None,
                    name: func
                        .get("name")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    description: func
                        .get("description")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    input_schema: func.get("parameters").cloned(),
                })
            }
        })
        .collect()
}

/// Merges a tool-use block into the last assistant message if possible.
///
/// Returns `None` if merged, or `Some(block)` if a new message is needed.
fn merge_tool_use_into_assistant(
    messages: &mut [Message],
    block: ContentBlock,
) -> Option<ContentBlock> {
    if let Some(last) = messages.last_mut() {
        if last.role == "assistant" {
            match &mut last.content {
                MessageContent::Blocks(blocks) => {
                    blocks.push(block);
                    return None;
                }
                MessageContent::Text(text) => {
                    let mut blocks = Vec::new();
                    if !text.is_empty() {
                        blocks.push(ContentBlock::text(std::mem::take(text), None));
                    }
                    blocks.push(block);
                    last.content = MessageContent::Blocks(blocks);
                    return None;
                }
            }
        }
    }
    Some(block)
}

/// Merges a tool-result block into the last user message if it only contains tool results.
///
/// Returns `None` if merged, or `Some(block)` if a new message is needed.
fn merge_tool_result_into_user(
    messages: &mut [Message],
    block: ContentBlock,
) -> Option<ContentBlock> {
    if let Some(last) = messages.last_mut() {
        if last.role == "user" {
            if let MessageContent::Blocks(ref mut existing) = &mut last.content {
                if existing.iter().all(|b| b.is_tool_result()) {
                    existing.push(block);
                    return None;
                }
            }
        }
    }
    Some(block)
}

/// Transforms a [`ResponsesRequest`] into a [`CanonicalRequest`].
///
/// # Errors
///
/// Returns a `String` description if the input items contain
/// an unrecognised variant that cannot be mapped to the canonical format.
pub fn transform_responses_to_canonical(req: ResponsesRequest) -> Result<CanonicalRequest, String> {
    let mut messages: Vec<Message> = Vec::new();
    let mut system_prompt: Option<SystemPrompt> = None;

    // instructions → system prompt
    if let Some(instructions) = &req.instructions {
        system_prompt = Some(SystemPrompt::Text(instructions.clone()));
    }

    match &req.input {
        ResponsesInput::Text(text) => {
            messages.push(Message {
                role: "user".to_string(),
                content: MessageContent::Text(text.clone()),
            });
        }
        ResponsesInput::Items(items) => {
            for item in items {
                match item {
                    InputItem::Message { role, content } => {
                        if role == "system" {
                            // Merge into system prompt
                            let text = extract_input_text(content);
                            system_prompt = Some(match system_prompt.take() {
                                Some(SystemPrompt::Text(existing)) => {
                                    SystemPrompt::Text(format!("{}\n{}", existing, text))
                                }
                                _ => SystemPrompt::Text(text),
                            });
                        } else {
                            messages.push(Message {
                                role: role.clone(),
                                content: MessageContent::Text(extract_input_text(content)),
                            });
                        }
                    }
                    InputItem::FunctionCall {
                        id,
                        call_id,
                        name,
                        arguments,
                    } => {
                        // function_call → assistant message with tool_use block
                        let tool_id = id
                            .as_deref()
                            .or(call_id.as_deref())
                            .unwrap_or("call_unknown")
                            .to_string();
                        let input: serde_json::Value =
                            serde_json::from_str(arguments).unwrap_or_default();
                        let block = ContentBlock::tool_use(tool_id, name.clone(), input);

                        if let Some(remaining) = merge_tool_use_into_assistant(&mut messages, block)
                        {
                            messages.push(Message {
                                role: "assistant".to_string(),
                                content: MessageContent::Blocks(vec![remaining]),
                            });
                        }
                    }
                    InputItem::FunctionCallOutput { call_id, output } => {
                        // function_call_output → user message with tool_result block
                        let block = ContentBlock::Known(KnownContentBlock::ToolResult {
                            tool_use_id: call_id.clone(),
                            content: ToolResultContent::Text(output.clone()),
                            is_error: false,
                            cache_control: None,
                        });

                        if let Some(remaining) = merge_tool_result_into_user(&mut messages, block) {
                            messages.push(Message {
                                role: "user".to_string(),
                                content: MessageContent::Blocks(vec![remaining]),
                            });
                        }
                    }
                }
            }
        }
    }

    let max_tokens = req
        .max_output_tokens
        .unwrap_or_else(|| models::default_max_tokens(&req.model));

    let extensions = crate::models::extensions::RequestExtensions {
        reasoning_effort: req.reasoning.as_ref().and_then(|r| r.effort.clone()),
        parallel_tool_calls: req.parallel_tool_calls,
        service_tier: req.service_tier,
        ..Default::default()
    };

    Ok(CanonicalRequest {
        model: req.model,
        messages,
        max_tokens,
        thinking: None,
        temperature: req.temperature,
        top_p: req.top_p,
        top_k: None,
        stop_sequences: None,
        stream: req.stream,
        metadata: None,
        system: system_prompt,
        tools: req.tools.as_ref().map(|t| convert_tools(t)),
        tool_choice: None,
        extensions,
    })
}

/// Transforms a [`ProviderResponse`] into a [`ResponsesResponse`].
pub fn transform_canonical_to_responses(
    response: ProviderResponse,
    model: String,
) -> ResponsesResponse {
    let mut output: Vec<OutputItem> = Vec::new();
    let mut text_parts: Vec<String> = Vec::new();

    for block in &response.content {
        match block {
            ContentBlock::Known(KnownContentBlock::Text { text, .. }) if !text.is_empty() => {
                text_parts.push(text.clone());
            }
            ContentBlock::Known(KnownContentBlock::ToolUse { id, name, input }) => {
                // Flush accumulated text as a message before function call
                if !text_parts.is_empty() {
                    output.push(OutputItem::Message {
                        id: format!("msg_{}", uuid::Uuid::new_v4().simple()),
                        role: "assistant",
                        content: vec![OutputContent::OutputText {
                            text: std::mem::take(&mut text_parts).join(""),
                        }],
                        status: "completed",
                    });
                }

                output.push(OutputItem::FunctionCall {
                    id: format!("fc_{}", uuid::Uuid::new_v4().simple()),
                    call_id: id.clone(),
                    name: name.clone(),
                    arguments: serde_json::to_string(input).unwrap_or_default(),
                    status: "completed",
                });
            }
            // Thinking blocks are ignored in Responses API output
            _ => {}
        }
    }

    // Flush remaining text
    if !text_parts.is_empty() {
        output.push(OutputItem::Message {
            id: format!("msg_{}", uuid::Uuid::new_v4().simple()),
            role: "assistant",
            content: vec![OutputContent::OutputText {
                text: text_parts.join(""),
            }],
            status: "completed",
        });
    }

    ResponsesResponse {
        id: format!("resp_{}", uuid::Uuid::new_v4().simple()),
        object: "response",
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        model,
        output,
        status: "completed",
        usage: ResponsesUsage {
            input_tokens: response.usage.input_tokens,
            output_tokens: response.usage.output_tokens,
            total_tokens: response.usage.input_tokens + response.usage.output_tokens,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_input_roundtrip() {
        let req = ResponsesRequest {
            model: "gpt-5.4".to_string(),
            instructions: Some("You are helpful.".to_string()),
            input: ResponsesInput::Text("Hello world".to_string()),
            stream: None,
            tools: None,
            reasoning: None,
            temperature: None,
            top_p: None,
            max_output_tokens: None,
            previous_response_id: None,
            store: None,
            parallel_tool_calls: None,
            service_tier: None,
        };

        let canonical = transform_responses_to_canonical(req).unwrap();
        assert_eq!(canonical.model, "gpt-5.4");
        match &canonical.system {
            Some(SystemPrompt::Text(t)) => assert_eq!(t, "You are helpful."),
            other => panic!("Expected SystemPrompt::Text, got {:?}", other),
        }
        assert_eq!(canonical.messages.len(), 1);
        assert_eq!(canonical.messages[0].role, "user");
    }

    #[test]
    fn function_call_items() {
        let req = ResponsesRequest {
            model: "gpt-5.3-codex".to_string(),
            instructions: None,
            input: ResponsesInput::Items(vec![
                InputItem::Message {
                    role: "user".to_string(),
                    content: InputContent::Text("List files".to_string()),
                },
                InputItem::FunctionCall {
                    id: Some("call_1".to_string()),
                    call_id: None,
                    name: "ls".to_string(),
                    arguments: r#"{"path":"."}"#.to_string(),
                },
                InputItem::FunctionCallOutput {
                    call_id: "call_1".to_string(),
                    output: "file1.rs\nfile2.rs".to_string(),
                },
            ]),
            stream: None,
            tools: None,
            reasoning: None,
            temperature: None,
            top_p: None,
            max_output_tokens: None,
            previous_response_id: None,
            store: None,
            parallel_tool_calls: None,
            service_tier: None,
        };

        let canonical = transform_responses_to_canonical(req).unwrap();
        assert_eq!(canonical.messages.len(), 3);
        assert_eq!(canonical.messages[0].role, "user");
        assert_eq!(canonical.messages[1].role, "assistant");
        assert_eq!(canonical.messages[2].role, "user");
    }

    #[test]
    fn tools_flat_format() {
        let tools_json = serde_json::json!([{
            "type": "function",
            "name": "get_weather",
            "description": "Gets weather",
            "parameters": {"type": "object", "properties": {"city": {"type": "string"}}}
        }]);
        let tools: Vec<serde_json::Value> = serde_json::from_value(tools_json).unwrap();
        let converted = convert_tools(&tools);
        assert_eq!(converted.len(), 1);
        assert_eq!(converted[0].name.as_deref(), Some("get_weather"));
        assert_eq!(converted[0].description.as_deref(), Some("Gets weather"));
        assert!(converted[0].input_schema.is_some());
    }

    #[test]
    fn canonical_to_responses_text() {
        use crate::providers::Usage;
        let response = ProviderResponse {
            id: "msg_123".to_string(),
            r#type: "message".to_string(),
            role: "assistant".to_string(),
            content: vec![ContentBlock::text("Hello!".to_string(), None)],
            model: "gpt-5.4".to_string(),
            stop_reason: Some("end_turn".to_string()),
            stop_sequence: None,
            usage: Usage {
                input_tokens: 10,
                output_tokens: 5,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        };

        let resp = transform_canonical_to_responses(response, "gpt-5.4".to_string());
        assert_eq!(resp.object, "response");
        assert_eq!(resp.status, "completed");
        assert_eq!(resp.output.len(), 1);
        assert_eq!(resp.usage.total_tokens, 15);
    }

    #[test]
    fn canonical_to_responses_tool_use() {
        use crate::providers::Usage;
        let response = ProviderResponse {
            id: "msg_456".to_string(),
            r#type: "message".to_string(),
            role: "assistant".to_string(),
            content: vec![
                ContentBlock::text("Let me check.".to_string(), None),
                ContentBlock::tool_use(
                    "call_abc".to_string(),
                    "get_weather".to_string(),
                    serde_json::json!({"city": "Paris"}),
                ),
            ],
            model: "gpt-5.4".to_string(),
            stop_reason: Some("tool_use".to_string()),
            stop_sequence: None,
            usage: Usage {
                input_tokens: 20,
                output_tokens: 15,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        };

        let resp = transform_canonical_to_responses(response, "gpt-5.4".to_string());
        assert_eq!(resp.output.len(), 2);
        // First should be message, second should be function_call
        match &resp.output[0] {
            OutputItem::Message { content, .. } => {
                assert_eq!(content.len(), 1);
            }
            _ => panic!("Expected Message"),
        }
        match &resp.output[1] {
            OutputItem::FunctionCall { name, call_id, .. } => {
                assert_eq!(name, "get_weather");
                assert_eq!(call_id, "call_abc");
            }
            _ => panic!("Expected FunctionCall"),
        }
    }
}

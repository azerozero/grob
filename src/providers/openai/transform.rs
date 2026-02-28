use super::types::*;
use crate::models::{AnthropicRequest, MessageContent};
use crate::providers::error::ProviderError;
use crate::providers::{ContentBlock, KnownContentBlock, ProviderResponse, Usage};

/// Transform Anthropic request format to OpenAI Chat Completions format.
///
/// Handles structural differences between the two APIs:
/// - `tool_use` blocks → `tool_calls` array on assistant messages
/// - `tool_result` blocks → separate `tool` role messages
/// - `image` blocks → `image_url` content parts with data URI encoding
/// - `thinking` blocks → dropped (OpenAI doesn't support this)
pub(crate) fn transform_request(
    request: &AnthropicRequest,
) -> Result<OpenAIRequest, ProviderError> {
    let mut openai_messages = Vec::new();

    // Add system message if present
    if let Some(ref system) = request.system {
        let system_text = system.to_text();
        openai_messages.push(OpenAIMessage {
            role: "system".to_string(),
            content: Some(OpenAIContent::String(system_text)),
            reasoning: None,
            tool_calls: None,
            tool_call_id: None,
        });
    }

    // Transform messages
    for msg in &request.messages {
        match &msg.content {
            MessageContent::Text(text) => {
                openai_messages.push(OpenAIMessage {
                    role: msg.role.clone(),
                    content: Some(OpenAIContent::String(text.clone())),
                    reasoning: None,
                    tool_calls: None,
                    tool_call_id: None,
                });
            }
            MessageContent::Blocks(blocks) => {
                transform_block_message(&msg.role, blocks, &mut openai_messages);
            }
        }
    }

    // Transform tools if present
    let tools = transform_tools(request);

    // Request usage data in streaming responses
    let stream_options = if request.stream == Some(true) {
        Some(OpenAIStreamOptions {
            include_usage: true,
        })
    } else {
        None
    };

    Ok(OpenAIRequest {
        model: request.model.clone(),
        messages: openai_messages,
        max_tokens: Some(request.max_tokens),
        temperature: request.temperature,
        top_p: request.top_p,
        stop: request.stop_sequences.clone(),
        stream: request.stream,
        stream_options,
        tools,
        tool_choice: transform_tool_choice(request),
    })
}

/// Transform a message with content blocks into OpenAI messages.
fn transform_block_message(
    role: &str,
    blocks: &[ContentBlock],
    openai_messages: &mut Vec<OpenAIMessage>,
) {
    let tool_results = extract_tool_results(blocks);
    let tool_calls = extract_tool_calls(blocks);
    let content_parts = extract_content_parts(blocks);

    // Add separate tool result messages FIRST (OpenAI requires this ordering)
    for (tool_use_id, result_content) in tool_results {
        openai_messages.push(OpenAIMessage {
            role: "tool".to_string(),
            content: Some(OpenAIContent::String(result_content)),
            reasoning: None,
            tool_calls: None,
            tool_call_id: Some(tool_use_id),
        });
    }

    // Then add main message with content and/or tool_calls
    if !content_parts.is_empty() || !tool_calls.is_empty() {
        let content = if content_parts.is_empty() {
            None
        } else if content_parts.len() == 1 {
            if let OpenAIContentPart::Text { text } = &content_parts[0] {
                Some(OpenAIContent::String(text.clone()))
            } else {
                Some(OpenAIContent::Parts(content_parts.clone()))
            }
        } else {
            Some(OpenAIContent::Parts(content_parts))
        };

        openai_messages.push(OpenAIMessage {
            role: role.to_string(),
            content,
            reasoning: None,
            tool_calls: if tool_calls.is_empty() {
                None
            } else {
                Some(tool_calls)
            },
            tool_call_id: None,
        });
    }
}

/// Extract tool_result blocks as (tool_use_id, content) pairs.
fn extract_tool_results(blocks: &[ContentBlock]) -> Vec<(String, String)> {
    blocks
        .iter()
        .filter_map(|block| {
            if let ContentBlock::Known(KnownContentBlock::ToolResult {
                tool_use_id,
                content,
                is_error,
                ..
            }) = block
            {
                let result_content = if *is_error {
                    tracing::debug!(
                        "Tool result is_error=true for {}, prefixing content",
                        tool_use_id
                    );
                    format!("[SYSTEM: Tools are disabled during warmup. Do NOT call any tools. Wait for the next user message before attempting any tool use.]\n{content}")
                } else {
                    content.to_string()
                };
                Some((tool_use_id.clone(), result_content))
            } else {
                None
            }
        })
        .collect()
}

/// Extract tool_use blocks as OpenAI tool calls.
fn extract_tool_calls(blocks: &[ContentBlock]) -> Vec<OpenAIToolCall> {
    blocks
        .iter()
        .filter_map(|block| {
            if let ContentBlock::Known(KnownContentBlock::ToolUse { id, name, input }) = block {
                Some(OpenAIToolCall {
                    id: id.clone(),
                    r#type: "function".to_string(),
                    function: OpenAIFunctionCall {
                        name: name.clone(),
                        arguments: serde_json::to_string(input).unwrap_or_default(),
                    },
                })
            } else {
                None
            }
        })
        .collect()
}

/// Extract text and image content parts (excluding tool blocks and thinking).
fn extract_content_parts(blocks: &[ContentBlock]) -> Vec<OpenAIContentPart> {
    let mut parts = Vec::new();
    for block in blocks {
        match block {
            ContentBlock::Known(KnownContentBlock::Text { text, .. }) => {
                parts.push(OpenAIContentPart::Text { text: text.clone() });
            }
            ContentBlock::Known(KnownContentBlock::Image { source }) => {
                let url = if source.r#type == "base64" {
                    let media_type = source.media_type.as_deref().unwrap_or("image/png");
                    let data = source.data.as_deref().unwrap_or("");
                    format!("data:{};base64,{}", media_type, data)
                } else if let Some(url) = &source.url {
                    url.clone()
                } else {
                    continue;
                };
                parts.push(OpenAIContentPart::ImageUrl {
                    image_url: OpenAIImageUrl { url },
                });
            }
            // ToolUse, ToolResult, Thinking, Unknown — handled elsewhere or skipped
            _ => {}
        }
    }
    parts
}

/// Transform Anthropic tool definitions to OpenAI format.
fn transform_tools(request: &AnthropicRequest) -> Option<Vec<OpenAITool>> {
    request.tools.as_ref().map(|anthropic_tools| {
        anthropic_tools
            .iter()
            .filter_map(|tool| {
                Some(OpenAITool {
                    r#type: "function".to_string(),
                    function: OpenAIFunctionDef {
                        name: tool.name.as_ref()?.clone(),
                        description: tool.description.clone(),
                        parameters: tool.input_schema.clone(),
                    },
                })
            })
            .collect()
    })
}

/// Transform Anthropic tool_choice to OpenAI format.
fn transform_tool_choice(request: &AnthropicRequest) -> Option<serde_json::Value> {
    request.tool_choice.as_ref().and_then(|tc| {
        let tc_type = tc.get("type").and_then(|v| v.as_str()).unwrap_or("");
        match tc_type {
            "auto" => Some(serde_json::json!("auto")),
            "any" => Some(serde_json::json!("required")),
            "tool" => {
                let name = tc.get("name").and_then(|v| v.as_str()).unwrap_or("");
                Some(serde_json::json!({
                    "type": "function",
                    "function": { "name": name }
                }))
            }
            _ => None,
        }
    })
}

/// Transform OpenAI Chat Completions response to Anthropic Messages format.
pub(crate) fn transform_response(response: OpenAIResponse) -> ProviderResponse {
    let choice = match response.choices.into_iter().next() {
        Some(c) => c,
        None => {
            return ProviderResponse {
                id: response.id,
                r#type: "message".to_string(),
                role: "assistant".to_string(),
                content: vec![],
                model: response.model,
                stop_reason: Some("error".to_string()),
                stop_sequence: None,
                usage: Usage {
                    input_tokens: 0,
                    output_tokens: 0,
                    cache_creation_input_tokens: None,
                    cache_read_input_tokens: None,
                },
            };
        }
    };

    let mut content_blocks = Vec::new();

    // Add reasoning as thinking block
    if let Some(reasoning) = choice.message.reasoning {
        if !reasoning.is_empty() {
            content_blocks.push(ContentBlock::thinking(serde_json::json!({
                "thinking": reasoning
            })));
        }
    }

    // Extract text content
    let text = match choice.message.content {
        Some(OpenAIContent::String(s)) => s,
        Some(OpenAIContent::Parts(parts)) => parts
            .iter()
            .filter_map(|part| {
                if let OpenAIContentPart::Text { text } = part {
                    Some(text.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join("\n"),
        None => String::new(),
    };

    if !text.is_empty() {
        content_blocks.push(ContentBlock::text(text, None));
    }

    // Transform tool_calls to tool_use content blocks
    if let Some(tool_calls) = choice.message.tool_calls {
        for tool_call in tool_calls {
            let input = serde_json::from_str(&tool_call.function.arguments)
                .unwrap_or(serde_json::json!({}));
            content_blocks.push(ContentBlock::tool_use(
                tool_call.id,
                tool_call.function.name,
                input,
            ));
        }
    }

    // Map OpenAI finish_reason to Anthropic stop_reason
    let stop_reason = choice.finish_reason.map(|reason| match reason.as_str() {
        "stop" => "end_turn".to_string(),
        "length" => "max_tokens".to_string(),
        "tool_calls" => "tool_use".to_string(),
        _ => "end_turn".to_string(),
    });

    ProviderResponse {
        id: response.id,
        r#type: "message".to_string(),
        role: "assistant".to_string(),
        content: content_blocks,
        model: response.model,
        stop_reason,
        stop_sequence: None,
        usage: Usage {
            input_tokens: response.usage.prompt_tokens,
            output_tokens: response.usage.completion_tokens,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
    }
}

/// Parse SSE response from ChatGPT Codex and extract content blocks.
///
/// Finds the `response.completed` event and extracts reasoning + message output.
pub(crate) fn parse_sse_response(sse_text: &str) -> Result<Vec<ContentBlock>, ProviderError> {
    let lines: Vec<&str> = sse_text.lines().collect();

    for (i, line) in lines.iter().enumerate() {
        if !line.starts_with("event: response.completed") {
            continue;
        }

        let Some(data_line) = lines.get(i + 1) else {
            continue;
        };
        let Some(json_str) = data_line.strip_prefix("data: ") else {
            continue;
        };
        let Ok(json) = serde_json::from_str::<serde_json::Value>(json_str) else {
            continue;
        };

        let Some(output) = json
            .get("response")
            .and_then(|r| r.get("output"))
            .and_then(|v| v.as_array())
        else {
            continue;
        };

        let content_blocks: Vec<ContentBlock> = output
            .iter()
            .filter_map(extract_codex_output_block)
            .collect();

        if !content_blocks.is_empty() {
            return Ok(content_blocks);
        }
    }

    Err(ProviderError::ApiError {
        status: 500,
        message: "Failed to parse SSE response: no content found".to_string(),
    })
}

/// Extract a content block from a Codex output item.
fn extract_codex_output_block(item: &serde_json::Value) -> Option<ContentBlock> {
    let output_type = item.get("type").and_then(|v| v.as_str())?;
    let text = item
        .get("content")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|first| first.get("text"))
        .and_then(|v| v.as_str())?;

    match output_type {
        "reasoning" => Some(ContentBlock::thinking(serde_json::json!({
            "thinking": text
        }))),
        "message" => Some(ContentBlock::text(text.to_string(), None)),
        _ => None,
    }
}

/// Transform Anthropic request to OpenAI Responses API format.
pub(crate) fn transform_to_responses_request(
    request: &AnthropicRequest,
    codex_instructions: &str,
) -> Result<OpenAIResponsesRequest, ProviderError> {
    let instructions = codex_instructions.to_string();
    let mut messages = Vec::new();

    // Add system message as user message (Codex doesn't have separate system role)
    if let Some(ref system) = request.system {
        messages.push(OpenAIResponsesMessage {
            role: "user".to_string(),
            content: Some(system.to_text()),
        });
    }

    for msg in &request.messages {
        let content = match &msg.content {
            MessageContent::Text(text) => text.clone(),
            MessageContent::Blocks(blocks) => {
                let text = blocks
                    .iter()
                    .filter_map(|block| block.as_text().map(|s| s.to_string()))
                    .collect::<Vec<_>>()
                    .join("\n");
                if text.is_empty() {
                    String::new()
                } else {
                    text
                }
            }
        };

        messages.push(OpenAIResponsesMessage {
            role: msg.role.clone(),
            content: Some(content),
        });
    }

    Ok(OpenAIResponsesRequest {
        model: request.model.clone(),
        input: OpenAIResponsesInput::Messages(messages),
        instructions,
        store: false,
        stream: true,
    })
}

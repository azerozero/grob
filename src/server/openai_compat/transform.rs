use crate::models::{
    self, CanonicalRequest, ContentBlock, KnownContentBlock, MessageContent, SystemPrompt, Tool,
    ToolResultContent,
};
use crate::providers::ProviderResponse;

use super::types::*;

/// Parse a data URI image into an Anthropic ImageSource (base64).
/// Returns `None` if the URI is malformed.
fn parse_data_uri_image(url: &str) -> Option<ContentBlock> {
    let comma_idx = url.find(',')?;
    let header = &url[..comma_idx];
    let data = &url[comma_idx + 1..];
    let media_type = if header.contains("image/jpeg") {
        "image/jpeg"
    } else if header.contains("image/png") {
        "image/png"
    } else if header.contains("image/gif") {
        "image/gif"
    } else if header.contains("image/webp") {
        "image/webp"
    } else {
        "image/png"
    };
    Some(ContentBlock::image(crate::models::ImageSource {
        r#type: "base64".to_string(),
        media_type: Some(media_type.to_string()),
        data: Some(data.to_string()),
        url: None,
    }))
}

/// Converts OpenAI content to canonical MessageContent.
pub(crate) fn openai_content_to_canonical(content: Option<OpenAIContent>) -> MessageContent {
    match content {
        Some(OpenAIContent::String(text)) => MessageContent::Text(text),
        Some(OpenAIContent::Parts(parts)) => {
            let blocks: Vec<ContentBlock> = parts
                .iter()
                .filter_map(|part| match part {
                    OpenAIContentPart::Text { text } => {
                        Some(ContentBlock::text(text.clone(), None))
                    }
                    OpenAIContentPart::ImageUrl { image_url } => {
                        if image_url.url.starts_with("data:") {
                            parse_data_uri_image(&image_url.url)
                        } else {
                            Some(ContentBlock::image(crate::models::ImageSource {
                                r#type: "url".to_string(),
                                media_type: None,
                                data: None,
                                url: Some(image_url.url.clone()),
                            }))
                        }
                    }
                })
                .collect();
            if blocks.is_empty() {
                MessageContent::Text(String::new())
            } else {
                MessageContent::Blocks(blocks)
            }
        }
        None => MessageContent::Text(String::new()),
    }
}

/// Extract text from OpenAI content (string or parts).
pub(crate) fn extract_text(content: OpenAIContent) -> String {
    match content {
        OpenAIContent::String(s) => s,
        OpenAIContent::Parts(parts) => parts
            .iter()
            .filter_map(|p| {
                if let OpenAIContentPart::Text { text } = p {
                    Some(text.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join("\n"),
    }
}

/// Convert an OpenAI assistant message (with optional tool_calls) to Anthropic blocks.
fn convert_assistant_message(msg: OpenAIMessage) -> crate::models::Message {
    let mut blocks: Vec<ContentBlock> = Vec::new();

    if let Some(openai_content) = msg.content {
        match openai_content {
            OpenAIContent::String(text) if !text.is_empty() => {
                blocks.push(ContentBlock::text(text, None));
            }
            OpenAIContent::Parts(parts) => {
                for part in &parts {
                    if let OpenAIContentPart::Text { text } = part {
                        if !text.is_empty() {
                            blocks.push(ContentBlock::text(text.clone(), None));
                        }
                    }
                }
            }
            _ => {}
        }
    }

    if let Some(tool_calls) = msg.tool_calls {
        for tc in tool_calls {
            let input: serde_json::Value = serde_json::from_str(&tc.function.arguments)
                .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));
            blocks.push(ContentBlock::tool_use(tc.id, tc.function.name, input));
        }
    }

    if blocks.is_empty() {
        blocks.push(ContentBlock::text(String::new(), None));
    }

    crate::models::Message {
        role: "assistant".to_string(),
        content: MessageContent::Blocks(blocks),
    }
}

/// Convert OpenAI tools JSON to Anthropic Tool format.
fn convert_tools(tools: &[serde_json::Value]) -> Vec<Tool> {
    tools
        .iter()
        .filter_map(|t| {
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
        })
        .collect()
}

/// Convert OpenAI tool_choice to Anthropic format.
fn convert_tool_choice(tc: &serde_json::Value) -> Option<serde_json::Value> {
    if let Some(s) = tc.as_str() {
        match s {
            "auto" | "none" => Some(serde_json::json!({"type": "auto"})),
            "required" => Some(serde_json::json!({"type": "any"})),
            _ => None,
        }
    } else if let Some(obj) = tc.as_object() {
        if obj.get("type").and_then(|v| v.as_str()) == Some("function") {
            let name = obj
                .get("function")
                .and_then(|f| f.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("");
            Some(serde_json::json!({"type": "tool", "name": name}))
        } else {
            None
        }
    } else {
        None
    }
}

/// Transforms an OpenAI request into a [`CanonicalRequest`].
pub fn transform_openai_to_canonical(
    openai_req: OpenAIRequest,
) -> Result<CanonicalRequest, String> {
    // Cap pre-allocation to prevent memory exhaustion from malicious input.
    let mut messages = Vec::with_capacity(openai_req.messages.len().min(1024));
    let mut system_prompt: Option<SystemPrompt> = None;

    for msg in openai_req.messages {
        match msg.role.as_str() {
            "system" => {
                if let Some(content) = msg.content {
                    system_prompt = Some(SystemPrompt::Text(extract_text(content)));
                }
            }
            "user" => {
                messages.push(crate::models::Message {
                    role: "user".to_string(),
                    content: openai_content_to_canonical(msg.content),
                });
            }
            "assistant" => {
                messages.push(convert_assistant_message(msg));
            }
            "tool" => {
                let tool_use_id = msg.tool_call_id.unwrap_or_default();
                let text = msg.content.map(extract_text).unwrap_or_default();
                let block = ContentBlock::Known(KnownContentBlock::ToolResult {
                    tool_use_id,
                    content: ToolResultContent::Text(text),
                    is_error: false,
                    cache_control: None,
                });

                // Try to merge into previous user message (consecutive tool results)
                if let Some(last) = messages.last_mut() {
                    if last.role == "user" {
                        if let MessageContent::Blocks(ref mut existing) = &mut last.content {
                            if existing.iter().all(|b| b.is_tool_result()) {
                                existing.push(block);
                                continue;
                            }
                        }
                    }
                }

                messages.push(crate::models::Message {
                    role: "user".to_string(),
                    content: MessageContent::Blocks(vec![block]),
                });
            }
            _ => {
                tracing::warn!("Skipping unsupported message role: {}", msg.role);
            }
        }
    }

    let max_tokens = openai_req
        .max_tokens
        .unwrap_or_else(|| models::default_max_tokens(&openai_req.model));

    let extensions = crate::models::extensions::RequestExtensions {
        response_format: openai_req.response_format,
        reasoning_effort: openai_req.reasoning_effort,
        seed: openai_req.seed,
        frequency_penalty: openai_req.frequency_penalty,
        presence_penalty: openai_req.presence_penalty,
        parallel_tool_calls: openai_req.parallel_tool_calls,
        user: openai_req.user,
        logprobs: openai_req.logprobs,
        top_logprobs: openai_req.top_logprobs,
        service_tier: openai_req.service_tier,
        ..Default::default()
    };

    Ok(CanonicalRequest {
        model: openai_req.model,
        messages,
        max_tokens,
        thinking: None,
        temperature: openai_req.temperature,
        top_p: openai_req.top_p,
        top_k: None,
        stop_sequences: openai_req.stop,
        stream: openai_req.stream,
        metadata: None,
        system: system_prompt,
        tools: openai_req.tools.as_ref().map(|tools| convert_tools(tools)),
        tool_choice: openai_req
            .tool_choice
            .as_ref()
            .and_then(convert_tool_choice),
        extensions,
    })
}

/// Transforms a [`ProviderResponse`] into an OpenAI-compatible response.
pub fn transform_canonical_to_openai(
    anthropic_resp: ProviderResponse,
    model: String,
) -> OpenAIResponse {
    let mut text_parts: Vec<String> = Vec::with_capacity(anthropic_resp.content.len().min(1024));
    let mut tool_calls: Vec<OpenAIToolCall> = Vec::new();

    for block in &anthropic_resp.content {
        match block {
            ContentBlock::Known(KnownContentBlock::Text { text, .. }) => {
                if !text.is_empty() {
                    text_parts.push(text.clone());
                }
            }
            ContentBlock::Known(KnownContentBlock::ToolUse { id, name, input }) => {
                tool_calls.push(OpenAIToolCall {
                    id: id.clone(),
                    r#type: "function".to_string(),
                    function: OpenAIFunction {
                        name: name.clone(),
                        arguments: serde_json::to_string(input).unwrap_or_default(),
                    },
                });
            }
            _ => {} // skip thinking, images, etc.
        }
    }

    let content = if text_parts.is_empty() {
        None
    } else {
        Some(text_parts.join("\n"))
    };
    let tool_calls_out = if tool_calls.is_empty() {
        None
    } else {
        Some(tool_calls)
    };

    // Map finish_reason
    let finish_reason = anthropic_resp.stop_reason.as_ref().map(|reason| {
        match reason.as_str() {
            "end_turn" => "stop",
            "max_tokens" => "length",
            "stop_sequence" => "stop",
            "tool_use" => "tool_calls",
            _ => "stop",
        }
        .to_string()
    });

    OpenAIResponse {
        id: anthropic_resp.id,
        object: "chat.completion".to_string(),
        created: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        model,
        choices: vec![OpenAIChoice {
            index: 0,
            message: OpenAIResponseMessage {
                role: anthropic_resp.role,
                content,
                tool_calls: tool_calls_out,
            },
            finish_reason,
        }],
        usage: OpenAIUsage {
            prompt_tokens: anthropic_resp.usage.input_tokens,
            completion_tokens: anthropic_resp.usage.output_tokens,
            total_tokens: anthropic_resp.usage.input_tokens + anthropic_resp.usage.output_tokens,
        },
    }
}

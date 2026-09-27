use super::reasoning_store::{self, ReasoningStore};
use super::types::*;
use crate::models::{CanonicalRequest, Message, MessageContent};
use crate::providers::error::{is_context_window_exceeded_message, ProviderError};
use crate::providers::streaming::parse_sse_events;
use crate::providers::{CodexOptions, ContentBlock, KnownContentBlock, ProviderResponse, Usage};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use thiserror::Error;

/// Errors raised while translating a [`CanonicalRequest`] into OpenAI wire format.
///
/// These map to user-visible 4xx responses since the offending data is
/// always client-supplied (e.g. malformed tool-use input). The provider layer
/// converts them to [`ProviderError::SerializationError`] for the existing
/// error pipeline.
#[derive(Debug, Error)]
pub(crate) enum TransformError {
    /// Failed to serialize a `tool_use` block's `input` field as JSON.
    ///
    /// OpenAI requires tool arguments as a JSON-encoded string; if the canonical
    /// `Value` (or wrapped `Serialize` payload) cannot round-trip through
    /// `serde_json::to_string`, surface the error rather than sending an empty
    /// string upstream — empty arguments either parse-error in OpenAI or cause
    /// the model to invoke the tool with no input, both of which were
    /// previously silent.
    #[error("failed to serialize tool_use input for tool '{tool_name}': {source}")]
    ToolInputSerialization {
        /// Name of the tool whose input failed to serialize.
        tool_name: String,
        /// Underlying serde_json error.
        #[source]
        source: serde_json::Error,
    },
    /// Client-supplied OpenAI tool metadata cannot be translated safely.
    #[error("{message}")]
    RequestValidation {
        /// Redacted validation message safe to return to callers.
        message: String,
    },
}

impl From<TransformError> for ProviderError {
    fn from(err: TransformError) -> Self {
        match err {
            TransformError::ToolInputSerialization { source, .. } => {
                ProviderError::SerializationError(source)
            }
            TransformError::RequestValidation { message } => ProviderError::InvalidRequest(message),
        }
    }
}

/// Serializes a tool-use input value as a JSON string, attaching the tool name on failure.
///
/// # Errors
///
/// Returns [`TransformError::ToolInputSerialization`] if the value cannot be
/// encoded as JSON.
pub(crate) fn serialize_tool_input<T: Serialize>(
    input: &T,
    tool_name: &str,
) -> Result<String, TransformError> {
    serde_json::to_string(input).map_err(|source| TransformError::ToolInputSerialization {
        tool_name: tool_name.to_string(),
        source,
    })
}

/// Transform Anthropic request format to OpenAI Chat Completions format.
///
/// Handles structural differences between the two APIs:
/// - `tool_use` blocks → `tool_calls` array on assistant messages
/// - `tool_result` blocks → separate `tool` role messages
/// - `image` blocks → `image_url` content parts with data URI encoding
/// - `thinking` blocks → dropped (OpenAI doesn't support this)
/// - System role: hoisted to the top-level `system` message exactly once,
///   even if the canonical `messages` array also contains a system entry.
///
/// # Errors
///
/// Returns [`TransformError::ToolInputSerialization`] if a `tool_use`
/// block's `input` cannot be serialized as JSON.
pub(crate) fn transform_request(
    request: &CanonicalRequest,
) -> Result<OpenAIRequest, TransformError> {
    let mut openai_messages = Vec::new();

    // Add system message if present
    if let Some(ref system) = request.system {
        let system_text = system.to_text();
        openai_messages.push(OpenAIMessage {
            role: "system".to_string(),
            content: Some(OpenAIContent::String(system_text)),
            name: request.extensions.openai_system_name.clone(),
            reasoning: None,
            tool_calls: None,
            tool_call_id: None,
        });
    }

    // Transform messages.
    //
    // NOTE: A canonical `system` was already hoisted to the top-level OpenAI
    // `system` message above. Drop any residual system-role entries from the
    // messages array to prevent duplicate system messages in the OpenAI
    // payload (audit Bug #3 — clients may send `[user, system, assistant]`
    // and grob previously emitted two `role:"system"` messages).
    for (message_index, msg) in request.messages.iter().enumerate() {
        if msg.role == "system" {
            tracing::debug!(
                "Dropping system-role message from canonical messages array (already hoisted to top-level system)"
            );
            continue;
        }
        match &msg.content {
            MessageContent::Text(text) => {
                openai_messages.push(OpenAIMessage {
                    role: msg.role.clone(),
                    content: Some(OpenAIContent::String(text.clone())),
                    name: request
                        .extensions
                        .openai_message_names
                        .get(message_index)
                        .cloned()
                        .flatten(),
                    reasoning: None,
                    tool_calls: None,
                    tool_call_id: None,
                });
            }
            MessageContent::Blocks(blocks) => {
                let name = request
                    .extensions
                    .openai_message_names
                    .get(message_index)
                    .cloned()
                    .flatten();
                transform_block_message(&msg.role, name, blocks, &mut openai_messages)?;
            }
        }
    }

    // Invariant: at most one system message (the hoisted one at index 0)
    // remains in the OpenAI payload.
    debug_assert!(
        openai_messages
            .iter()
            .filter(|m| m.role == "system")
            .count()
            <= 1,
        "system role leaked into OpenAI messages array more than once"
    );

    // Transform tools if present
    let tools = transform_tools(request)?;
    let tool_choice = transform_tool_choice(request, tools.as_ref())?;

    // Request usage data in streaming responses
    let stream_options = if request.stream == Some(true) {
        Some(OpenAIStreamOptions {
            include_usage: true,
        })
    } else {
        None
    };

    let ext = &request.extensions;

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
        tool_choice,
        // Restore provider-specific fields from extensions
        response_format: ext.response_format.clone(),
        reasoning_effort: ext.reasoning_effort.clone(),
        seed: ext.seed,
        frequency_penalty: ext.frequency_penalty,
        presence_penalty: ext.presence_penalty,
        parallel_tool_calls: ext.parallel_tool_calls,
        user: ext.user.clone(),
        logprobs: ext.logprobs,
        top_logprobs: ext.top_logprobs,
        service_tier: ext.service_tier.clone(),
    })
}

/// Transform a message with content blocks into OpenAI messages.
fn transform_block_message(
    role: &str,
    name: Option<String>,
    blocks: &[ContentBlock],
    openai_messages: &mut Vec<OpenAIMessage>,
) -> Result<(), TransformError> {
    let tool_results = extract_tool_results(blocks);
    let tool_calls = extract_tool_calls(blocks)?;
    let content_parts = extract_content_parts(blocks);

    // Add separate tool result messages FIRST (OpenAI requires this ordering)
    for (tool_use_id, result_content) in tool_results {
        openai_messages.push(OpenAIMessage {
            role: "tool".to_string(),
            content: Some(OpenAIContent::String(result_content)),
            name: None,
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
            name,
            reasoning: None,
            tool_calls: if tool_calls.is_empty() {
                None
            } else {
                Some(tool_calls)
            },
            tool_call_id: None,
        });
    }
    Ok(())
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

/// Filters Anthropic `tool_use` content blocks and reshapes them as OpenAI `tool_calls` entries with JSON-stringified arguments.
///
/// # Errors
///
/// Returns [`TransformError::ToolInputSerialization`] if any tool's `input`
/// fails JSON serialization. Previously substituted an empty string, which
/// caused either an OpenAI parse error or a tool invocation with no
/// arguments — both silent.
fn extract_tool_calls(blocks: &[ContentBlock]) -> Result<Vec<OpenAIToolCall>, TransformError> {
    let mut calls = Vec::new();
    for block in blocks {
        if let ContentBlock::Known(KnownContentBlock::ToolUse { id, name, input }) = block {
            let arguments = serialize_tool_input(input, name)?;
            calls.push(OpenAIToolCall {
                id: id.clone(),
                r#type: "function".to_string(),
                function: OpenAIFunctionCall {
                    name: name.clone(),
                    arguments,
                },
            });
        }
    }
    Ok(calls)
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
fn transform_tools(request: &CanonicalRequest) -> Result<Option<Vec<OpenAITool>>, TransformError> {
    let Some(anthropic_tools) = request.tools.as_ref() else {
        return Ok(None);
    };

    let mut tools = Vec::with_capacity(anthropic_tools.len());
    for (index, tool) in anthropic_tools.iter().enumerate() {
        let Some(name) = tool
            .name
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty())
        else {
            return Err(TransformError::RequestValidation {
                message: format!(
                    "OpenAI tool definition at index {index} is missing a non-empty name"
                ),
            });
        };
        tools.push(OpenAITool {
            r#type: "function".to_string(),
            function: OpenAIFunctionDef {
                name: name.to_string(),
                description: tool.description.clone(),
                parameters: tool.input_schema.clone(),
            },
        });
    }

    Ok((!tools.is_empty()).then_some(tools))
}

/// Transform Anthropic tool_choice to OpenAI format.
fn transform_tool_choice(
    request: &CanonicalRequest,
    tools: Option<&Vec<OpenAITool>>,
) -> Result<Option<serde_json::Value>, TransformError> {
    let Some(tc) = request.tool_choice.as_ref() else {
        return Ok(None);
    };
    let tc_type = tc.get("type").and_then(|v| v.as_str()).unwrap_or("");
    match tc_type {
        "auto" => Ok(tools.map(|_| serde_json::json!("auto"))),
        "any" => {
            if tools.is_none() {
                return Err(TransformError::RequestValidation {
                    message: "OpenAI tool_choice 'any' requires at least one tool definition"
                        .to_string(),
                });
            }
            Ok(Some(serde_json::json!("required")))
        }
        "tool" => {
            let Some(name) = tc
                .get("name")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|name| !name.is_empty())
            else {
                return Err(TransformError::RequestValidation {
                    message: "OpenAI named tool_choice requires a non-empty name".to_string(),
                });
            };
            if let Some(tools) = tools {
                if !tools.iter().any(|tool| tool.function.name == name) {
                    return Err(TransformError::RequestValidation {
                        message: format!("OpenAI tool_choice references unknown tool '{name}'"),
                    });
                }
            } else {
                return Err(TransformError::RequestValidation {
                    message: "OpenAI named tool_choice requires declared tools".to_string(),
                });
            }
            Ok(Some(serde_json::json!({
                "type": "function",
                "function": { "name": name }
            })))
        }
        other => Err(TransformError::RequestValidation {
            message: format!("unsupported OpenAI tool_choice type '{other}'"),
        }),
    }
}

fn parse_provider_tool_arguments(
    context: &str,
    tool_name: &str,
    arguments: &str,
) -> Result<serde_json::Value, ProviderError> {
    serde_json::from_str(arguments).map_err(|e| {
        ProviderError::ProtocolError(format!(
            "OpenAI returned malformed tool arguments for {context} tool '{tool_name}': {e}"
        ))
    })
}

/// Transform OpenAI Chat Completions response to Anthropic Messages format.
pub(crate) fn transform_response(
    response: OpenAIResponse,
) -> Result<ProviderResponse, ProviderError> {
    let cached_tokens = response.usage.cached_tokens();
    let usage = Usage {
        input_tokens: response.usage.prompt_tokens.saturating_sub(cached_tokens),
        output_tokens: response.usage.completion_tokens,
        cache_creation_input_tokens: None,
        cache_read_input_tokens: (cached_tokens > 0).then_some(cached_tokens),
    };
    let choice = match response.choices.into_iter().next() {
        Some(c) => c,
        None => {
            return Ok(ProviderResponse {
                id: response.id,
                r#type: "message".to_string(),
                role: "assistant".to_string(),
                content: vec![],
                model: response.model,
                stop_reason: Some("error".to_string()),
                stop_sequence: None,
                usage,
            });
        }
    };

    let mut content_blocks = Vec::new();
    let mut salvaged_tool_count = 0u32;

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

    // Scan the text for tool calls the model leaked as plain content (Codex
    // sometimes does this) and re-emit them as structured tool_use blocks.
    let mut salvaged_tool = false;
    if !text.is_empty() {
        for event in super::tool_salvage::salvage_complete(&text) {
            match event {
                super::tool_salvage::SalvageEvent::Text(t) => {
                    if !t.is_empty() {
                        content_blocks.push(ContentBlock::text(t, None));
                    }
                }
                super::tool_salvage::SalvageEvent::ToolCall(call) => {
                    salvaged_tool = true;
                    salvaged_tool_count += 1;
                    content_blocks.push(ContentBlock::tool_use(
                        format!("toolu_salvaged_{salvaged_tool_count}"),
                        call.name,
                        call.input,
                    ));
                }
            }
        }
    }

    // Transform tool_calls to tool_use content blocks
    if let Some(tool_calls) = choice.message.tool_calls {
        for tool_call in tool_calls {
            let input = parse_provider_tool_arguments(
                "Chat Completions",
                &tool_call.function.name,
                &tool_call.function.arguments,
            )?;
            content_blocks.push(ContentBlock::tool_use(
                tool_call.id,
                tool_call.function.name,
                input,
            ));
        }
    }

    // Map OpenAI finish_reason to Anthropic stop_reason. A salvaged tool call
    // overrides a plain "stop" so the client runs the recovered tool.
    let stop_reason = choice.finish_reason.map(|reason| match reason.as_str() {
        "stop" if salvaged_tool => "tool_use".to_string(),
        "stop" => "end_turn".to_string(),
        "length" => "max_tokens".to_string(),
        "tool_calls" => "tool_use".to_string(),
        _ => "end_turn".to_string(),
    });

    Ok(ProviderResponse {
        id: response.id,
        r#type: "message".to_string(),
        role: "assistant".to_string(),
        content: content_blocks,
        model: response.model,
        stop_reason,
        stop_sequence: None,
        usage,
    })
}

mod responses_request;
mod responses_sse;
#[cfg(test)]
mod tests;

pub(crate) use responses_request::{transform_to_responses_request, CodexTuning};
pub(crate) use responses_sse::parse_sse_response;

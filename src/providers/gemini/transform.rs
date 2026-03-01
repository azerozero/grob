use super::types::*;
use crate::models::{AnthropicRequest, ContentBlock, KnownContentBlock, MessageContent};
use crate::providers::{ProviderError, ProviderResponse, Usage};
use std::collections::HashMap;

/// Remove JSON Schema metadata fields that Gemini API doesn't support
pub(super) fn clean_json_schema(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            // Remove JSON Schema metadata fields
            map.remove("$schema");
            map.remove("$id");
            map.remove("$ref");
            map.remove("$comment");
            map.remove("exclusiveMinimum");
            map.remove("exclusiveMaximum");
            map.remove("definitions");
            map.remove("$defs");

            // Recursively clean nested objects
            for (_, v) in map.iter_mut() {
                clean_json_schema(v);
            }
        }
        serde_json::Value::Array(arr) => {
            // Recursively clean array elements
            for item in arr.iter_mut() {
                clean_json_schema(item);
            }
        }
        _ => {}
    }
}

/// Convert a single Anthropic content block to a Gemini part.
pub(super) fn convert_block(
    block: &ContentBlock,
    tool_id_to_name: &HashMap<String, String>,
) -> Option<GeminiPart> {
    match block {
        ContentBlock::Known(KnownContentBlock::Text { text, .. }) => {
            Some(GeminiPart::Text { text: text.clone() })
        }
        ContentBlock::Known(KnownContentBlock::Image { source }) => {
            let (media_type, data) = (source.media_type.as_ref()?, source.data.as_ref()?);
            Some(GeminiPart::InlineData {
                inline_data: GeminiInlineData {
                    mime_type: media_type.clone(),
                    data: data.clone(),
                },
            })
        }
        ContentBlock::Known(KnownContentBlock::Thinking { raw }) => {
            let thinking = raw.get("thinking").and_then(|v| v.as_str())?;
            Some(GeminiPart::Text {
                text: thinking.to_string(),
            })
        }
        ContentBlock::Known(KnownContentBlock::ToolUse { name, input, .. }) => {
            Some(GeminiPart::FunctionCall {
                function_call: GeminiFunctionCall {
                    name: name.clone(),
                    args: input.clone(),
                },
            })
        }
        ContentBlock::Known(KnownContentBlock::ToolResult {
            tool_use_id,
            content,
            ..
        }) => {
            let fn_name = tool_id_to_name
                .get(tool_use_id)
                .cloned()
                .unwrap_or_else(|| tool_use_id.clone());
            Some(GeminiPart::FunctionResponse {
                function_response: GeminiFunctionResponse {
                    name: fn_name,
                    response: serde_json::json!({ "content": content.to_string() }),
                },
            })
        }
        _ => None,
    }
}

/// Convert Anthropic tools to Gemini tool format.
pub(super) fn convert_tools(tools: &[crate::models::Tool]) -> Vec<GeminiTool> {
    let mut gemini_tools = Vec::new();
    let mut function_declarations = Vec::new();

    for tool in tools {
        match tool.name.as_deref().unwrap_or("") {
            "WebSearch" => gemini_tools.push(GeminiTool::GoogleSearch {
                google_search: GoogleSearchTool {},
            }),
            "WebFetch" => gemini_tools.push(GeminiTool::UrlContext {
                url_context: UrlContextTool {},
            }),
            _ => {
                let mut parameters = tool.input_schema.clone().unwrap_or_default();
                clean_json_schema(&mut parameters);
                if let Some(name) = &tool.name {
                    function_declarations.push(GeminiFunctionDeclaration {
                        name: name.clone(),
                        description: tool.description.clone().unwrap_or_default(),
                        parameters,
                    });
                }
            }
        }
    }

    if !function_declarations.is_empty() {
        gemini_tools.push(GeminiTool::FunctionDeclarations {
            function_declarations,
        });
    }
    gemini_tools
}

/// Convert Anthropic tool_choice to Gemini tool_config.
pub(super) fn convert_tool_config(tc: &serde_json::Value) -> Option<GeminiToolConfig> {
    let tc_type = tc.get("type").and_then(|v| v.as_str()).unwrap_or("");
    let (mode, names) = match tc_type {
        "auto" => ("AUTO", None),
        "any" => ("ANY", None),
        "tool" => {
            let name = tc.get("name").and_then(|v| v.as_str()).unwrap_or("");
            ("ANY", Some(vec![name.to_string()]))
        }
        _ => return None,
    };
    Some(GeminiToolConfig {
        function_calling_config: GeminiFunctionCallingConfig {
            mode: mode.to_string(),
            allowed_function_names: names,
        },
    })
}

/// Transform Anthropic request to Gemini format
pub(super) fn transform_request(
    request: &AnthropicRequest,
    supports_tools: bool,
) -> Result<GeminiRequest, ProviderError> {
    let system_instruction = request
        .system
        .as_ref()
        .map(|system| GeminiSystemInstruction {
            parts: vec![GeminiPart::Text {
                text: system.to_text(),
            }],
        });

    // Build tool_use_id → name map for resolving tool_result references
    let tool_id_to_name: HashMap<String, String> = request
        .messages
        .iter()
        .flat_map(|msg| match &msg.content {
            MessageContent::Blocks(blocks) => blocks.as_slice(),
            _ => &[],
        })
        .filter_map(|block| match block {
            ContentBlock::Known(KnownContentBlock::ToolUse { id, name, .. }) => {
                Some((id.clone(), name.clone()))
            }
            _ => None,
        })
        .collect();

    // Transform messages
    let contents: Vec<GeminiContent> = request
        .messages
        .iter()
        .filter_map(|msg| {
            let role = match msg.role.as_str() {
                "user" => "user",
                "assistant" => "model",
                _ => return None,
            };
            let parts = match &msg.content {
                MessageContent::Text(text) => vec![GeminiPart::Text { text: text.clone() }],
                MessageContent::Blocks(blocks) => blocks
                    .iter()
                    .filter_map(|b| convert_block(b, &tool_id_to_name))
                    .collect(),
            };
            if parts.is_empty() {
                return None;
            }
            Some(GeminiContent {
                role: role.to_string(),
                parts,
            })
        })
        .collect();

    let tools = if supports_tools {
        request.tools.as_ref().map(|tools| convert_tools(tools))
    } else {
        None
    };

    Ok(GeminiRequest {
        contents,
        system_instruction,
        generation_config: Some(GeminiGenerationConfig {
            temperature: request.temperature,
            top_p: request.top_p,
            top_k: Some(40),
            max_output_tokens: Some(request.max_tokens as i32),
            stop_sequences: request.stop_sequences.clone(),
        }),
        tools,
        tool_config: request.tool_choice.as_ref().and_then(convert_tool_config),
    })
}

/// Transform Gemini response to Anthropic format
pub(super) fn transform_response(
    response: GeminiResponse,
    model: String,
) -> Result<ProviderResponse, ProviderError> {
    let candidate = response
        .candidates
        .first()
        .ok_or_else(|| ProviderError::ApiError {
            status: 500,
            message: "No candidates in response".to_string(),
        })?;

    let mut has_function_call = false;
    let mut tool_call_counter = 0u32;
    let content: Vec<ContentBlock> = candidate
        .content
        .parts
        .iter()
        .filter_map(|part| match part {
            GeminiPart::Text { text } => Some(ContentBlock::text(text.clone(), None)),
            GeminiPart::FunctionCall { function_call } => {
                has_function_call = true;
                tool_call_counter += 1;
                let id = format!("toolu_{:012x}", tool_call_counter);
                Some(ContentBlock::tool_use(
                    id,
                    function_call.name.clone(),
                    function_call.args.clone(),
                ))
            }
            _ => None, // Skip InlineData, FunctionResponse in model output
        })
        .collect();

    let stop_reason = if has_function_call {
        Some("tool_use".to_string())
    } else {
        match candidate.finish_reason.as_deref() {
            Some("STOP") => Some("end_turn".to_string()),
            Some("MAX_TOKENS") => Some("max_tokens".to_string()),
            _ => None,
        }
    };

    let usage = Usage {
        input_tokens: response
            .usage_metadata
            .as_ref()
            .and_then(|u| u.prompt_token_count)
            .unwrap_or(0) as u32,
        output_tokens: response
            .usage_metadata
            .as_ref()
            .and_then(|u| u.candidates_token_count)
            .unwrap_or(0) as u32,
        cache_creation_input_tokens: None,
        cache_read_input_tokens: None,
    };

    Ok(ProviderResponse {
        id: format!("gemini-{}", chrono::Utc::now().timestamp_millis()),
        r#type: "message".to_string(),
        role: "assistant".to_string(),
        content,
        model,
        stop_reason,
        stop_sequence: None,
        usage,
    })
}

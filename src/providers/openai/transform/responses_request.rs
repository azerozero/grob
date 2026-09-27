//! Canonical request -> OpenAI Responses API request (Codex CLI wire format):
//! instructions, input items, reasoning replay, tools and service tier.

use super::*;

/// Instructions used when the client forwards its own tools.
///
/// The full Codex CLI prompt describes built-in `shell`/`apply_patch`/`update_plan`
/// tools that do not exist when a client like Claude Code provides its own tool
/// set — that mismatch makes the model invent tool calls (often leaked as text).
/// This minimal preamble keeps the backend-expected "Codex" identity but defers
/// all tool behavior to the request's tools and the client's own system prompt.
const CODEX_TOOL_INSTRUCTIONS: &str = "You are Codex, based on GPT-5, operating as a coding agent. \
The harness provides its own system prompt and a set of tools in this request. Use ONLY those \
provided tools through the function-calling interface to take actions — do not assume any built-in \
`shell`, `apply_patch`, or `update_plan` tool exists, and never emit a tool call as plain text or \
inside a code block. When you need to run a command, read, or edit, call the matching provided tool \
with its required arguments. Omit optional arguments that are unset; never send an empty string as a \
placeholder for a missing optional argument.";

/// Per-call knobs for the Codex (OpenAI Responses API) transform.
///
/// Bundles the operator-forced overrides with the provider's [`CodexOptions`]
/// so the resolver functions stay parameterised instead of reaching for global
/// state. Build it with [`CodexTuning::from_options`].
#[derive(Clone, Copy)]
pub(crate) struct CodexTuning<'a> {
    /// Operator-forced reasoning effort (highest precedence). `None` = auto.
    pub forced_effort: Option<&'a str>,
    /// Operator-forced service tier (e.g. `"priority"`). `None` = request/none.
    pub forced_service_tier: Option<&'a str>,
    /// Models eligible for the `priority` tier and default `xhigh` effort.
    pub priority_models: &'a [String],
    /// When `true`, map the extended-thinking budget → effort (opt-in).
    pub reasoning_auto_map: bool,
    /// Thinking budget at/above which auto-map selects `xhigh` (else `medium`).
    pub reasoning_xhigh_min_budget: u32,
    /// Store of encrypted reasoning items to splice back into `input`.
    ///
    /// `None` when `codex.reasoning_continuity` is off, which is the default.
    pub reasoning_store: Option<&'a ReasoningStore>,
}

impl<'a> CodexTuning<'a> {
    /// Borrows a provider's [`CodexOptions`] alongside any forced overrides.
    pub(crate) fn from_options(
        opts: &'a CodexOptions,
        forced_effort: Option<&'a str>,
        forced_service_tier: Option<&'a str>,
    ) -> Self {
        Self {
            forced_effort,
            forced_service_tier,
            priority_models: &opts.priority_models,
            reasoning_auto_map: opts.reasoning_auto_map,
            reasoning_xhigh_min_budget: opts.reasoning_xhigh_min_budget,
            reasoning_store: None,
        }
    }

    /// Attaches the reasoning store, enabling cross-turn reasoning replay.
    pub(crate) fn with_reasoning_store(mut self, store: Option<&'a ReasoningStore>) -> Self {
        self.reasoning_store = store;
        self
    }
}

/// Where to look up the reasoning items belonging to one conversation.
struct ReasoningReplay<'a> {
    store: &'a ReasoningStore,
    /// The prefix hash that identifies this conversation, shared with
    /// `prompt_cache_key`.
    conversation: &'a str,
}

/// Transform Anthropic request to OpenAI Responses API format.
pub(crate) fn transform_to_responses_request(
    request: &CanonicalRequest,
    codex_instructions: &str,
    tuning: &CodexTuning<'_>,
) -> Result<OpenAIResponsesRequest, ProviderError> {
    let tools = transform_responses_tools(request)?;
    let tool_choice = transform_responses_tool_choice(request, tools.as_ref())?;

    let instructions = responses_instructions(request, codex_instructions, tools.is_some());

    // Derived before the items are built so it can double as the reasoning
    // store's conversation key; it only reads the reusable prefix.
    let prompt_cache_key =
        derive_prompt_cache_key(&instructions, tools.as_deref(), request.messages.first());
    let replay = tuning.reasoning_store.map(|store| ReasoningReplay {
        store,
        conversation: &prompt_cache_key,
    });

    let items = responses_input_items(request, replay.as_ref())?;

    let reasoning = resolve_reasoning_effort(request, tuning)
        .map(|effort| serde_json::json!({ "effort": effort }));
    // Reasoning models only engage prompt caching under `store = false` when the
    // request opts into encrypted reasoning state (Codex CLI does this); without
    // it gpt-5.5 returns zero cached tokens.
    let include = reasoning
        .is_some()
        .then(|| vec!["reasoning.encrypted_content".to_string()]);

    Ok(OpenAIResponsesRequest {
        model: request.model.clone(),
        input: OpenAIResponsesInput::Items(items),
        instructions,
        // The ChatGPT Codex backend REQUIRES store=false (returns 400 "Store must
        // be set to false" otherwise), so this is fixed for every path.
        store: false,
        stream: true,
        tool_choice,
        parallel_tool_calls: tools.as_ref().map(|_| true),
        tools,
        reasoning,
        service_tier: resolve_service_tier(request, tuning),
        prompt_cache_key: Some(prompt_cache_key),
        include,
    })
}

/// Selects the authoritative agent instructions for native and foreign clients.
fn responses_instructions(
    request: &CanonicalRequest,
    codex_instructions: &str,
    has_tools: bool,
) -> String {
    // Codex CLI requests carry their own authoritative Codex agent prompt as
    // `instructions` (canonical `system`). Forward it verbatim as the
    // top-level `instructions` so the backend stays in full agentic mode.
    // Demoting it to a user item (the foreign-client path) makes the model emit
    // a preamble and stop instead of calling the provided tools.
    if request.extensions.codex_native {
        request
            .system
            .as_ref()
            .map(|s| s.to_text())
            .unwrap_or_else(|| codex_instructions.to_string())
    } else if has_tools {
        // Forwarding tools and the full Codex CLI prompt at once makes a foreign
        // client's model call non-existent built-in tools, so defer to a preamble.
        CODEX_TOOL_INSTRUCTIONS.to_string()
    } else {
        codex_instructions.to_string()
    }
}

/// Preserves conversation order while translating messages, tools and reasoning.
fn responses_input_items(
    request: &CanonicalRequest,
    replay: Option<&ReasoningReplay<'_>>,
) -> Result<Vec<OpenAIResponsesItem>, ProviderError> {
    let mut items = Vec::new();

    // Codex has no separate system role; hoist the system prompt to a user item.
    // Skip on the codex-native path: the system is already the top-level
    // `instructions` above, so re-adding it here would duplicate it.
    if !request.extensions.codex_native {
        if let Some(ref system) = request.system {
            items.push(OpenAIResponsesItem::Message {
                role: "user".to_string(),
                content: Some(responses_message_content("user", system.to_text())),
            });
        }
    }

    for msg in &request.messages {
        // The ChatGPT Codex backend rejects `system`-role items ("System messages
        // are not allowed") — system guidance belongs in `instructions`. Fold any
        // system-role message (e.g. Claude Code `<system-reminder>` turns) into a
        // user item so its content survives.
        let role = if msg.role == "system" {
            "user"
        } else {
            msg.role.as_str()
        };
        match &msg.content {
            MessageContent::Text(text) => items.push(OpenAIResponsesItem::Message {
                role: role.to_string(),
                content: Some(responses_message_content(role, text.clone())),
            }),
            MessageContent::Blocks(blocks) => {
                push_blocks_as_items(&mut items, role, blocks, replay)?;
            }
        }
    }

    Ok(items)
}

/// Derives a stable `prompt_cache_key` from a request's reusable prefix.
///
/// OpenAI's prompt cache matches on the longest common token prefix of a
/// request; the `prompt_cache_key` routes requests that share that prefix to the
/// same cache node, which lifts hit rates on agent loops. Anthropic's surface
/// expresses this through explicit `cache_control` breakpoints, which the
/// Responses translation drops — so grob reconstructs an equivalent here.
///
/// The key hashes the parts that stay constant across one conversation's turns —
/// the resolved `instructions`, the tool definitions, and the first message —
/// so every turn of a session sends the same key while distinct sessions stay
/// separated. SHA-256 with a fixed truncation keeps it deterministic across
/// process restarts, preserving cache continuity.
fn derive_prompt_cache_key(
    instructions: &str,
    tools: Option<&[serde_json::Value]>,
    first_message: Option<&Message>,
) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;

    let mut hasher = Sha256::new();
    hasher.update(instructions.as_bytes());
    if let Some(tools) = tools {
        if let Ok(bytes) = serde_json::to_vec(tools) {
            hasher.update(&bytes);
        }
    }
    if let Some(message) = first_message {
        if let Ok(bytes) = serde_json::to_vec(message) {
            hasher.update(&bytes);
        }
    }

    // 128 bits of hex is collision-safe for cache routing and stays well under
    // the backend's key-length limit.
    let digest = hasher.finalize();
    let mut key = String::from("grob-");
    for byte in &digest[..16] {
        let _ = write!(key, "{byte:02x}");
    }
    key
}

/// Resolves the Codex `service_tier` (processing speed) for a request.
///
/// A provider-config value wins, then a `service_tier` request extension. The
/// value passes through verbatim — the backend validates it — so `"priority"`
/// (faster handling) works without a whitelist. `None` leaves the field unset.
fn resolve_service_tier(request: &CanonicalRequest, tuning: &CodexTuning<'_>) -> Option<String> {
    let tier = tuning
        .forced_service_tier
        .map(str::to_string)
        .or_else(|| request.extensions.service_tier.clone())
        .filter(|s| !s.is_empty())?;
    // The "priority" (1.5x) tier exists only on some models (by default gpt-5.5
    // and gpt-5.4 — see `CodexOptions::priority_models`); others reject it with a
    // 400. Drop it for unsupported models so a provider forcing
    // `service_tier = "priority"` does not break `think`/`background` routes
    // (which resolve to codex/mini models). Other tiers pass through.
    if tier == "priority" && !priority_tier_supported(&request.model, tuning.priority_models) {
        return None;
    }
    Some(tier)
}

/// Returns whether the model offers the Codex `priority` (1.5x) service tier.
///
/// The eligible set is configurable via [`CodexOptions::priority_models`]
/// (default `["gpt-5.5", "gpt-5.4"]`). An entry matches the model by exact name
/// or as a prefix; a prefix match excludes `-mini` fast-tier variants unless the
/// model is listed verbatim. The same set also gates the default `xhigh` effort.
fn priority_tier_supported(model: &str, priority_models: &[String]) -> bool {
    let m = model.to_ascii_lowercase();
    priority_models.iter().any(|entry| {
        let p = entry.to_ascii_lowercase();
        m == p || (m.starts_with(&p) && !m.contains("mini"))
    })
}

/// Resolves the Codex reasoning effort for a request.
///
/// Precedence:
/// 1. A provider-config `forced_effort` or an explicit `reasoning_effort`
///    request extension (e.g. from a Codex CLI client) — passed through verbatim
///    so newer tiers (e.g. `xhigh`) work without a grob release.
/// 2. If `reasoning_auto_map` is enabled, the effort auto-maps from the
///    request's extended-thinking budget (legacy behavior).
/// 3. Otherwise the flat default: `xhigh` for the priority/flagship models
///    (see [`priority_tier_supported`]), and `None` for the rest so the backend
///    applies its own default effort.
fn resolve_reasoning_effort(
    request: &CanonicalRequest,
    tuning: &CodexTuning<'_>,
) -> Option<String> {
    let supplied = tuning
        .forced_effort
        .map(str::to_string)
        .or_else(|| request.extensions.reasoning_effort.clone())
        .filter(|s| !s.is_empty());
    if let Some(effort) = supplied {
        return Some(effort);
    }
    if tuning.reasoning_auto_map {
        return Some(auto_map_thinking_effort(
            request,
            tuning.reasoning_xhigh_min_budget,
        ));
    }
    // Flat default: max out the flagship models, leave the rest to the backend.
    if priority_tier_supported(&request.model, tuning.priority_models) {
        Some("xhigh".to_string())
    } else {
        None
    }
}

/// Maps Anthropic extended-thinking config to a Codex reasoning-effort tier.
///
/// Only used in the opt-in `reasoning_auto_map` mode. No thinking (or an
/// explicitly `disabled` block) maps to `low` for snappy responses. Any other
/// thinking block means the client opted into extended reasoning, so it maps
/// high: Claude Code's adaptive mode (`type: "adaptive"`, no budget — the same
/// for every `think`/`think hard`/`ultrathink` keyword, so they cannot be told
/// apart) maps to `xhigh`, the backend's max tier; an explicit budget maps to
/// `xhigh` at/above `xhigh_min_budget`, else `medium`. Effort tiers:
/// `low` < `medium` < `high` < `xhigh` (`max` is rejected by the backend).
///
/// Note: Claude Code's `/effort` slider is client-internal and never reaches the
/// API, so it cannot be mapped here — only the thinking keywords, which set a
/// thinking block, do.
fn auto_map_thinking_effort(request: &CanonicalRequest, xhigh_min_budget: u32) -> String {
    let Some(thinking) = request.thinking.as_ref() else {
        return "low".to_string();
    };
    if thinking.r#type == "disabled" {
        return "low".to_string();
    }
    match thinking.budget_tokens {
        Some(budget) if budget >= xhigh_min_budget => "xhigh",
        Some(_) => "medium",
        // Adaptive thinking (no budget) is opt-in deep reasoning — give it the max.
        None => "xhigh",
    }
    .to_string()
}

/// Expands a message's content blocks into Responses items, preserving order.
///
/// Text and image blocks collapse into `message` items; `tool_use` blocks become
/// `function_call` items and `tool_result` blocks become `function_call_output`
/// items, keyed by the shared Anthropic tool-use id so the round-trip stays
/// correlated. Thinking blocks are dropped.
fn push_blocks_as_items(
    items: &mut Vec<OpenAIResponsesItem>,
    role: &str,
    blocks: &[ContentBlock],
    replay: Option<&ReasoningReplay<'_>>,
) -> Result<(), ProviderError> {
    // Buffered text is coalesced into one part; images interleave as their own
    // parts, so a "describe this" text + image turn stays a single message.
    let mut text = String::new();
    let mut parts: Vec<serde_json::Value> = Vec::new();

    for block in blocks {
        match block {
            ContentBlock::Known(KnownContentBlock::Text { text: t, .. }) => {
                if !text.is_empty() {
                    text.push('\n');
                }
                text.push_str(t);
            }
            ContentBlock::Known(KnownContentBlock::Image { source }) => {
                flush_text_part(role, &mut text, &mut parts);
                if let Some(part) = responses_image_part(source) {
                    parts.push(part);
                }
            }
            ContentBlock::Known(KnownContentBlock::ToolUse { id, name, input }) => {
                flush_message_parts(items, role, &mut text, &mut parts);
                // The backend requires each reasoning item to sit immediately
                // before the call it produced; anywhere else is a 400.
                if let Some(replay) = replay {
                    items.extend(
                        reasoning_store::replay(replay.store, replay.conversation, id)
                            .into_iter()
                            .map(OpenAIResponsesItem::Reasoning),
                    );
                }
                let arguments = serialize_tool_input(input, name)?;
                items.push(OpenAIResponsesItem::FunctionCall {
                    call_id: id.clone(),
                    name: name.clone(),
                    arguments,
                });
            }
            ContentBlock::Known(KnownContentBlock::ToolResult {
                tool_use_id,
                content,
                ..
            }) => {
                flush_message_parts(items, role, &mut text, &mut parts);
                items.push(OpenAIResponsesItem::FunctionCallOutput {
                    call_id: tool_use_id.clone(),
                    output: responses_tool_output(content),
                });
            }
            _ => {}
        }
    }

    flush_message_parts(items, role, &mut text, &mut parts);
    Ok(())
}

/// Appends the buffered text (if any) to `parts` as one typed text part.
fn flush_text_part(role: &str, text: &mut String, parts: &mut Vec<serde_json::Value>) {
    if !text.is_empty() {
        parts.push(responses_text_part(role, std::mem::take(text)));
    }
}

/// Flushes buffered text and image parts into a single `message` item.
fn flush_message_parts(
    items: &mut Vec<OpenAIResponsesItem>,
    role: &str,
    text: &mut String,
    parts: &mut Vec<serde_json::Value>,
) {
    flush_text_part(role, text, parts);
    if !parts.is_empty() {
        items.push(OpenAIResponsesItem::Message {
            role: role.to_string(),
            content: Some(serde_json::Value::Array(std::mem::take(parts))),
        });
    }
}

/// Builds one Responses-API typed text part.
///
/// The backend's prompt cache only matches when message content uses the
/// structured parts; a flat string defeats caching for reasoning models like
/// gpt-5.5. Assistant turns use `output_text`; every other role uses
/// `input_text`.
fn responses_text_part(role: &str, text: String) -> serde_json::Value {
    let part_type = if role == "assistant" {
        "output_text"
    } else {
        "input_text"
    };
    serde_json::json!({ "type": part_type, "text": text })
}

/// Wraps a text string as Responses-API message content (`[{"type":…,"text":…}]`).
fn responses_message_content(role: &str, text: String) -> serde_json::Value {
    serde_json::Value::Array(vec![responses_text_part(role, text)])
}

/// Serializes a tool result as a Responses `function_call_output.output`.
///
/// Text-only results stay a bare JSON string (unchanged wire shape, so the
/// prompt cache is undisturbed). When the tool returned an image, the output
/// becomes an array of `input_text`/`input_image` parts in original order — the
/// Codex backend accepts this and the model sees the actual pixels, instead of
/// the `[Image]` placeholder `Display` produced, which made it hallucinate.
pub(super) fn responses_tool_output(
    content: &crate::models::ToolResultContent,
) -> serde_json::Value {
    use crate::models::{KnownToolResultBlock, ToolResultBlock, ToolResultContent};

    let ToolResultContent::Blocks(blocks) = content else {
        return serde_json::Value::String(content.to_string());
    };
    let has_image = blocks.iter().any(|b| {
        matches!(
            b,
            ToolResultBlock::Known(KnownToolResultBlock::Image { .. })
        )
    });
    if !has_image {
        return serde_json::Value::String(content.to_string());
    }

    let mut parts: Vec<serde_json::Value> = Vec::new();
    let mut text = String::new();
    let flush_text = |text: &mut String, parts: &mut Vec<serde_json::Value>| {
        if !text.is_empty() {
            parts.push(serde_json::json!({ "type": "input_text", "text": std::mem::take(text) }));
        }
    };
    for block in blocks {
        match block {
            ToolResultBlock::Known(KnownToolResultBlock::Text { text: t }) => {
                if !text.is_empty() {
                    text.push('\n');
                }
                text.push_str(t);
            }
            ToolResultBlock::Known(KnownToolResultBlock::Image { source }) => {
                flush_text(&mut text, &mut parts);
                if let Some(part) = responses_image_part(source) {
                    parts.push(part);
                }
            }
            // Preserve unknown blocks as text rather than dropping them silently.
            ToolResultBlock::Unknown(v) => {
                if !text.is_empty() {
                    text.push('\n');
                }
                text.push_str(&v.to_string());
            }
        }
    }
    flush_text(&mut text, &mut parts);
    serde_json::Value::Array(parts)
}

/// Builds a Responses-API `input_image` part from an Anthropic image block.
///
/// Base64 sources become a `data:` URI; URL sources pass through. Returns `None`
/// when neither the inline data nor a URL is present (nothing to send).
fn responses_image_part(source: &crate::models::ImageSource) -> Option<serde_json::Value> {
    let image_url = if let Some(url) = source.url.as_ref().filter(|u| !u.is_empty()) {
        url.clone()
    } else {
        let data = source.data.as_ref().filter(|d| !d.is_empty())?;
        let media_type = source.media_type.as_deref().unwrap_or("image/png");
        format!("data:{media_type};base64,{data}")
    };
    // The Responses API takes `image_url` as a bare string, unlike Chat
    // Completions where it is an object.
    Some(serde_json::json!({ "type": "input_image", "image_url": image_url }))
}

/// Transforms Anthropic tool definitions into Responses-API (flattened) tools.
fn transform_responses_tools(
    request: &CanonicalRequest,
) -> Result<Option<Vec<serde_json::Value>>, ProviderError> {
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
            return Err(ProviderError::InvalidRequest(format!(
                "OpenAI Responses tool definition at index {index} is missing a non-empty name"
            )));
        };
        let mut entry = serde_json::json!({
            "type": "function",
            "name": name,
            "parameters": tool
                .input_schema
                .clone()
                .unwrap_or_else(|| serde_json::json!({ "type": "object", "properties": {} })),
        });
        if let Some(description) = &tool.description {
            entry["description"] = serde_json::Value::String(description.clone());
        }
        tools.push(entry);
    }

    Ok((!tools.is_empty()).then_some(tools))
}

/// Transforms Anthropic `tool_choice` into the Responses-API shape.
fn transform_responses_tool_choice(
    request: &CanonicalRequest,
    tools: Option<&Vec<serde_json::Value>>,
) -> Result<Option<serde_json::Value>, ProviderError> {
    let Some(tc) = request.tool_choice.as_ref() else {
        return Ok(None);
    };
    match tc.get("type").and_then(|v| v.as_str()).unwrap_or("") {
        "auto" => Ok(tools.map(|_| serde_json::json!("auto"))),
        "any" => {
            if tools.is_none() {
                return Err(ProviderError::InvalidRequest(
                    "OpenAI Responses tool_choice 'any' requires at least one tool definition"
                        .to_string(),
                ));
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
                return Err(ProviderError::InvalidRequest(
                    "OpenAI Responses named tool_choice requires a non-empty name".to_string(),
                ));
            };
            let Some(tools) = tools else {
                return Err(ProviderError::InvalidRequest(
                    "OpenAI Responses named tool_choice requires declared tools".to_string(),
                ));
            };
            if !tools
                .iter()
                .any(|tool| tool.get("name").and_then(|v| v.as_str()) == Some(name))
            {
                return Err(ProviderError::InvalidRequest(format!(
                    "OpenAI Responses tool_choice references unknown tool '{name}'"
                )));
            }
            Ok(Some(
                serde_json::json!({ "type": "function", "name": name }),
            ))
        }
        other => Err(ProviderError::InvalidRequest(format!(
            "unsupported OpenAI Responses tool_choice type '{other}'"
        ))),
    }
}

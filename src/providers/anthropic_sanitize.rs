//! Anthropic request sanitization: thinking block signature handling and tool ID normalization.

use super::constants::MIN_ANTHROPIC_SIGNATURE_LENGTH;
use crate::models::{CanonicalRequest, ContentBlock, KnownContentBlock, MessageContent};
use std::collections::HashMap;

/// Bidirectional map between sanitized (canonical) tool IDs and the originals
/// supplied by the client.
///
/// Anthropic enforces `^[a-zA-Z0-9_-]{1,64}$` on tool IDs, but downstream
/// clients (e.g. Claude Code) often track the *original* IDs they sent — IDs
/// minted by a previous OpenAI turn may include `.`, `:`, etc. When grob
/// rewrites those IDs before calling an Anthropic backend, the response must
/// echo the **original** form so the client can match its tool definitions.
///
/// Lookup is by canonical_id (the post-sanitization form that we send
/// upstream), returning the original_id we owe the client.
#[derive(Debug, Default, Clone)]
pub(super) struct OriginalToolIdMap {
    canonical_to_original: HashMap<String, String>,
}

impl OriginalToolIdMap {
    /// Creates an empty map.
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// Records a sanitization edit. No-op when the canonical form equals the
    /// original (i.e. no rewrite was needed).
    fn record(&mut self, canonical_id: &str, original_id: &str) {
        if canonical_id == original_id {
            return;
        }
        // Last writer wins on duplicate canonical IDs (rare; happens only if
        // two distinct originals collapse to the same canonical form).
        self.canonical_to_original
            .insert(canonical_id.to_string(), original_id.to_string());
    }

    /// Returns the original ID for a sanitized canonical ID, if any.
    pub(super) fn original_for(&self, canonical_id: &str) -> Option<&str> {
        self.canonical_to_original
            .get(canonical_id)
            .map(String::as_str)
    }

    /// Returns true if no rewrites were recorded — callers can skip the
    /// response walk entirely.
    pub(super) fn is_empty(&self) -> bool {
        self.canonical_to_original.is_empty()
    }
}

// Thinking block signature handling for Anthropic
//
// What we know works:
//   - Sending thinking blocks WITH valid Anthropic signatures → accepted
//   - Sending thinking blocks WITHOUT a signature field at all (unsigned) → accepted
//   - Omitting thinking blocks from prior turns entirely → accepted
//
// What doesn't work:
//   - Sending thinking blocks with invalid/non-Anthropic signatures → rejected
//   - Sending thinking blocks with signature field removed (was present, now absent) →
//     same as unsigned, should work (identical JSON), but untested in production
//   - Stripping just the signature field was rejected in testing with "Field required"
//
// Strategy:
//   1. Proactive: use heuristic to strip thinking blocks with non-Anthropic signatures
//      (Anthropic signatures are long base64 strings, 200+ chars)
//   2. Fallback: on any signature error from Anthropic, strip all signatures
//      (converting to unsigned blocks), and retry

/// Anthropic signatures are long base64 strings (200+ chars typically).
fn looks_like_anthropic_signature(sig: &str) -> bool {
    use base64::Engine;
    sig.len() >= MIN_ANTHROPIC_SIGNATURE_LENGTH
        && base64::engine::general_purpose::STANDARD
            .decode(sig)
            .is_ok()
}

/// Proactive: strip thinking blocks that don't look like they came from Anthropic.
/// Keeps unsigned blocks and blocks with valid-looking Anthropic signatures.
pub(super) fn strip_non_anthropic_thinking(request: &mut CanonicalRequest) {
    let mut stripped_count = 0;

    for message in &mut request.messages {
        if let MessageContent::Blocks(blocks) = &mut message.content {
            let before_len = blocks.len();
            blocks.retain(|block| match block {
                ContentBlock::Known(KnownContentBlock::Thinking { raw }) => {
                    match raw.get("signature").and_then(|v| v.as_str()) {
                        None => true,
                        Some(sig) if looks_like_anthropic_signature(sig) => true,
                        Some(_) => {
                            tracing::debug!(
                                "🧹 Stripping thinking block with non-Anthropic signature"
                            );
                            false
                        }
                    }
                }
                _ => true,
            });
            stripped_count += before_len - blocks.len();
        }
    }

    remove_empty_messages(request);

    if stripped_count > 0 {
        tracing::info!(
            "🧹 Stripped {} non-Anthropic thinking block(s)",
            stripped_count
        );
    }
}

/// Fallback: strip all signatures from thinking blocks, converting them to unsigned.
/// Used when Anthropic rejects a signature the heuristic thought was valid.
pub(super) fn strip_all_thinking_signatures(request: &mut CanonicalRequest) {
    let mut stripped_count = 0;

    for message in &mut request.messages {
        if let MessageContent::Blocks(blocks) = &mut message.content {
            for block in blocks.iter_mut() {
                if let ContentBlock::Known(KnownContentBlock::Thinking { raw }) = block {
                    if let Some(obj) = raw.as_object_mut() {
                        if obj.remove("signature").is_some() {
                            stripped_count += 1;
                        }
                    }
                }
            }
        }
    }

    if stripped_count > 0 {
        tracing::info!(
            "🧹 Fallback: stripped signatures from {} thinking block(s)",
            stripped_count
        );
    }
}

fn remove_empty_messages(request: &mut CanonicalRequest) {
    request.messages.retain(|msg| match &msg.content {
        MessageContent::Text(t) => !t.is_empty(),
        MessageContent::Blocks(b) => !b.is_empty(),
    });
}

/// Sanitize tool_use.id and tool_use_id fields to match Anthropic's pattern requirement.
///
/// Anthropic requires tool IDs to match: `^[a-zA-Z0-9_-]+`. Non-Anthropic
/// providers may generate IDs with invalid characters (e.g. OpenAI's
/// `functions.Bash:0`). This function rewrites them in-place and records each
/// (canonical, original) pair into `id_map` so the response path can restore
/// the original IDs before returning to the client (audit Bug #2 — silent
/// tool-result lookup failures when the client tries to match response IDs
/// against IDs it sent).
pub(super) fn sanitize_tool_use_ids(
    request: &mut CanonicalRequest,
    id_map: &mut OriginalToolIdMap,
) {
    let mut sanitized_count = 0;

    for message in &mut request.messages {
        if let MessageContent::Blocks(blocks) = &mut message.content {
            for block in blocks.iter_mut() {
                match block {
                    ContentBlock::Known(KnownContentBlock::ToolUse { id, name, input }) => {
                        let sanitized = sanitize_tool_id(id);
                        if sanitized != *id {
                            tracing::debug!("🔧 Sanitized tool_use.id: {} → {}", id, sanitized);
                            id_map.record(&sanitized, id);
                            *block = ContentBlock::tool_use(sanitized, name.clone(), input.clone());
                            sanitized_count += 1;
                        }
                    }
                    ContentBlock::Known(KnownContentBlock::ToolResult {
                        tool_use_id,
                        content,
                        is_error,
                        cache_control,
                    }) => {
                        let sanitized = sanitize_tool_id(tool_use_id);
                        if sanitized != *tool_use_id {
                            tracing::debug!(
                                "🔧 Sanitized tool_use_id: {} → {}",
                                tool_use_id,
                                sanitized
                            );
                            id_map.record(&sanitized, tool_use_id);
                            *block = ContentBlock::Known(KnownContentBlock::ToolResult {
                                tool_use_id: sanitized,
                                content: content.clone(),
                                is_error: *is_error,
                                cache_control: cache_control.clone(),
                            });
                            sanitized_count += 1;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    if sanitized_count > 0 {
        tracing::info!("🔧 Sanitized {} tool IDs for Anthropic", sanitized_count);
    }
}

/// Walks a provider response and replaces any sanitized (canonical) tool IDs
/// with the originals captured in `id_map`.
///
/// Applies to both `tool_use` blocks (assistant turn) and `tool_result`
/// blocks (rare in responses, but defended for completeness). No-op when the
/// map is empty.
pub(super) fn restore_original_tool_ids(
    response: &mut crate::providers::ProviderResponse,
    id_map: &OriginalToolIdMap,
) {
    if id_map.is_empty() {
        return;
    }

    let mut restored_count = 0usize;
    for block in response.content.iter_mut() {
        match block {
            ContentBlock::Known(KnownContentBlock::ToolUse { id, name, input }) => {
                if let Some(original) = id_map.original_for(id) {
                    tracing::debug!("🔁 Restored tool_use.id: {} → {}", id, original);
                    *block =
                        ContentBlock::tool_use(original.to_string(), name.clone(), input.clone());
                    restored_count += 1;
                }
            }
            ContentBlock::Known(KnownContentBlock::ToolResult {
                tool_use_id,
                content,
                is_error,
                cache_control,
            }) => {
                if let Some(original) = id_map.original_for(tool_use_id) {
                    tracing::debug!("🔁 Restored tool_use_id: {} → {}", tool_use_id, original);
                    *block = ContentBlock::Known(KnownContentBlock::ToolResult {
                        tool_use_id: original.to_string(),
                        content: content.clone(),
                        is_error: *is_error,
                        cache_control: cache_control.clone(),
                    });
                    restored_count += 1;
                }
            }
            _ => {}
        }
    }

    if restored_count > 0 {
        tracing::info!(
            "🔁 Restored {} original tool ID(s) on response",
            restored_count
        );
    }
}

/// Sanitize a tool ID to match pattern ^[a-zA-Z0-9_-]+
fn sanitize_tool_id(id: &str) -> String {
    id.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Message, ToolResultContent};
    use crate::providers::{ProviderResponse, Usage};

    fn user_message_with_blocks(blocks: Vec<ContentBlock>) -> Message {
        Message {
            role: "user".to_string(),
            content: MessageContent::Blocks(blocks),
        }
    }

    fn assistant_message_with_blocks(blocks: Vec<ContentBlock>) -> Message {
        Message {
            role: "assistant".to_string(),
            content: MessageContent::Blocks(blocks),
        }
    }

    fn empty_request() -> CanonicalRequest {
        CanonicalRequest {
            model: "claude-3-7-sonnet".to_string(),
            messages: Vec::new(),
            max_tokens: 100,
            thinking: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop_sequences: None,
            stream: None,
            metadata: None,
            system: None,
            tools: None,
            tool_choice: None,
            extensions: Default::default(),
        }
    }

    fn provider_response_with(blocks: Vec<ContentBlock>) -> ProviderResponse {
        ProviderResponse {
            id: "msg_x".to_string(),
            r#type: "message".to_string(),
            role: "assistant".to_string(),
            content: blocks,
            model: "claude-3-7-sonnet".to_string(),
            stop_reason: Some("end_turn".to_string()),
            stop_sequence: None,
            usage: Usage {
                input_tokens: 1,
                output_tokens: 1,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        }
    }

    #[test]
    fn tool_use_id_round_trip_preserves_original() {
        // Bug #2: a client previously routed via OpenAI sends back tool IDs
        // like `functions.Bash:0` (non-Anthropic). Grob sanitizes them for
        // the upstream call, then must restore the originals on the response
        // so the client can map response IDs to its tool definitions.
        let original_use_id = "functions.Bash:0";
        let original_result_id = "functions.Read:1";

        let mut req = empty_request();
        req.messages = vec![
            assistant_message_with_blocks(vec![ContentBlock::tool_use(
                original_use_id.to_string(),
                "Bash".to_string(),
                serde_json::json!({"command": "ls"}),
            )]),
            user_message_with_blocks(vec![ContentBlock::Known(KnownContentBlock::ToolResult {
                tool_use_id: original_result_id.to_string(),
                content: ToolResultContent::Text("done".to_string()),
                is_error: false,
                cache_control: None,
            })]),
        ];

        let mut id_map = OriginalToolIdMap::new();
        sanitize_tool_use_ids(&mut req, &mut id_map);

        // Sanity: the request now carries canonical IDs.
        let sanitized_use_id = "functions_Bash_0";
        let sanitized_result_id = "functions_Read_1";
        assert_eq!(
            id_map.original_for(sanitized_use_id),
            Some(original_use_id),
            "use id mapping missing"
        );
        assert_eq!(
            id_map.original_for(sanitized_result_id),
            Some(original_result_id),
            "result id mapping missing"
        );
        assert!(!id_map.is_empty());

        // The upstream response echoes the canonical ID (Anthropic enforces
        // the pattern and would reject the original) — restore it.
        let mut response = provider_response_with(vec![
            ContentBlock::tool_use(
                sanitized_use_id.to_string(),
                "Bash".to_string(),
                serde_json::json!({"command": "ls"}),
            ),
            ContentBlock::Known(KnownContentBlock::ToolResult {
                tool_use_id: sanitized_result_id.to_string(),
                content: ToolResultContent::Text("ok".to_string()),
                is_error: false,
                cache_control: None,
            }),
        ]);

        restore_original_tool_ids(&mut response, &id_map);

        // After restoration the response carries the originals the client
        // expects to round-trip with.
        match &response.content[0] {
            ContentBlock::Known(KnownContentBlock::ToolUse { id, .. }) => {
                assert_eq!(id, original_use_id);
            }
            other => panic!("expected ToolUse, got {:?}", other),
        }
        match &response.content[1] {
            ContentBlock::Known(KnownContentBlock::ToolResult { tool_use_id, .. }) => {
                assert_eq!(tool_use_id, original_result_id);
            }
            other => panic!("expected ToolResult, got {:?}", other),
        }
    }

    #[test]
    fn restore_is_noop_when_map_is_empty() {
        // Common case: client sent IDs that already match Anthropic's
        // pattern — nothing to record, nothing to restore.
        let mut req = empty_request();
        req.messages = vec![assistant_message_with_blocks(vec![ContentBlock::tool_use(
            "toolu_abc".to_string(),
            "weather".to_string(),
            serde_json::json!({}),
        )])];

        let mut id_map = OriginalToolIdMap::new();
        sanitize_tool_use_ids(&mut req, &mut id_map);
        assert!(id_map.is_empty());

        let mut response = provider_response_with(vec![ContentBlock::tool_use(
            "toolu_xyz".to_string(),
            "weather".to_string(),
            serde_json::json!({}),
        )]);
        restore_original_tool_ids(&mut response, &id_map);

        match &response.content[0] {
            ContentBlock::Known(KnownContentBlock::ToolUse { id, .. }) => {
                assert_eq!(id, "toolu_xyz", "untracked IDs must pass through unchanged");
            }
            other => panic!("expected ToolUse, got {:?}", other),
        }
    }

    #[test]
    fn restore_leaves_unmapped_ids_untouched() {
        // The map records a single rewrite; a different ID in the response
        // (e.g. a fresh Anthropic-generated one) must not be touched.
        let mut id_map = OriginalToolIdMap::new();
        id_map.record("functions_Bash_0", "functions.Bash:0");

        let mut response = provider_response_with(vec![
            ContentBlock::tool_use(
                "functions_Bash_0".to_string(),
                "Bash".to_string(),
                serde_json::json!({}),
            ),
            ContentBlock::tool_use(
                "toolu_fresh".to_string(),
                "weather".to_string(),
                serde_json::json!({}),
            ),
        ]);

        restore_original_tool_ids(&mut response, &id_map);
        match &response.content[0] {
            ContentBlock::Known(KnownContentBlock::ToolUse { id, .. }) => {
                assert_eq!(id, "functions.Bash:0");
            }
            other => panic!("expected ToolUse, got {:?}", other),
        }
        match &response.content[1] {
            ContentBlock::Known(KnownContentBlock::ToolUse { id, .. }) => {
                assert_eq!(id, "toolu_fresh");
            }
            other => panic!("expected ToolUse, got {:?}", other),
        }
    }
}

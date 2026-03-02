//! Anthropic request sanitization: thinking block signature handling and tool ID normalization.

use super::constants::MIN_ANTHROPIC_SIGNATURE_LENGTH;
use crate::models::{AnthropicRequest, ContentBlock, KnownContentBlock, MessageContent};

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
pub(super) fn strip_non_anthropic_thinking(request: &mut AnthropicRequest) {
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
pub(super) fn strip_all_thinking_signatures(request: &mut AnthropicRequest) {
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

fn remove_empty_messages(request: &mut AnthropicRequest) {
    request.messages.retain(|msg| match &msg.content {
        MessageContent::Text(t) => !t.is_empty(),
        MessageContent::Blocks(b) => !b.is_empty(),
    });
}

/// Sanitize tool_use.id and tool_use_id fields to match Anthropic's pattern requirement.
/// Anthropic requires tool IDs to match: ^[a-zA-Z0-9_-]+
/// Non-Anthropic providers may generate IDs with invalid characters.
pub(super) fn sanitize_tool_use_ids(request: &mut AnthropicRequest) {
    let mut sanitized_count = 0;

    for message in &mut request.messages {
        if let MessageContent::Blocks(blocks) = &mut message.content {
            for block in blocks.iter_mut() {
                match block {
                    ContentBlock::Known(KnownContentBlock::ToolUse { id, name, input }) => {
                        let sanitized = sanitize_tool_id(id);
                        if sanitized != *id {
                            tracing::debug!("🔧 Sanitized tool_use.id: {} → {}", id, sanitized);
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

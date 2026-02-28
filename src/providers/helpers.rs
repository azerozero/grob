use crate::models::{
    ContentBlock, CountTokensRequest, CountTokensResponse, KnownContentBlock, MessageContent,
};

use super::constants::CHARS_PER_TOKEN;

/// Character-based token estimation shared by providers without native token counting.
pub fn estimate_token_count(request: &CountTokensRequest) -> CountTokensResponse {
    let mut total_chars = 0;

    if let Some(ref system) = request.system {
        total_chars += system.to_text().len();
    }

    for msg in &request.messages {
        let content = match &msg.content {
            MessageContent::Text(text) => text.clone(),
            MessageContent::Blocks(blocks) => blocks
                .iter()
                .filter_map(|block| match block {
                    ContentBlock::Known(KnownContentBlock::Text { text, .. }) => Some(text.clone()),
                    ContentBlock::Known(KnownContentBlock::ToolResult { content, .. }) => {
                        Some(content.to_string())
                    }
                    ContentBlock::Known(KnownContentBlock::Thinking { raw }) => raw
                        .get("thinking")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("\n"),
        };
        total_chars += content.len();
    }

    let estimated_tokens = (total_chars / CHARS_PER_TOKEN) as u32;

    CountTokensResponse {
        input_tokens: estimated_tokens,
    }
}

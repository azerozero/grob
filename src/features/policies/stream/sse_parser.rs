//! Structural accessors for complete SSE events. Transport framing is upstream.

pub(super) fn event_json(bytes: &[u8]) -> Option<serde_json::Value> {
    let text = std::str::from_utf8(bytes).ok()?;
    let data = text
        .lines()
        .filter_map(|line| {
            line.strip_prefix("data:")
                .map(|v| v.strip_prefix(' ').unwrap_or(v))
        })
        .collect::<Vec<_>>()
        .join("\n");
    serde_json::from_str(&data).ok()
}

/// Extracts a tool name from a complete content-block-start event.
pub fn extract_tool_name(bytes: &[u8]) -> Option<String> {
    let value = event_json(bytes)?;
    if value["type"] != "content_block_start" || value["content_block"]["type"] != "tool_use" {
        return None;
    }
    value["content_block"]["name"].as_str().map(str::to_owned)
}

/// Extracts a content-block index without depending on JSON formatting.
pub fn extract_block_index(bytes: &[u8]) -> Option<u32> {
    event_json(bytes)?["index"].as_u64()?.try_into().ok()
}

/// Extracts and JSON-decodes input fragments for the selected block.
pub fn extract_partial_json(bytes: &[u8], target_index: u32) -> Option<String> {
    let value = event_json(bytes)?;
    if value["index"].as_u64()? != u64::from(target_index)
        || value["delta"]["type"] != "input_json_delta"
    {
        return None;
    }
    value["delta"]["partial_json"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(s: &str) -> Vec<u8> {
        s.as_bytes().to_vec()
    }

    #[test]
    fn test_extract_tool_name_found() {
        let data = chunk(
            r#"event: content_block_start
data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"x","name":"Bash"}}

"#,
        );
        assert_eq!(extract_tool_name(&data), Some("Bash".to_string()));
    }

    #[test]
    fn test_extract_tool_name_not_tool_use() {
        let data = chunk(
            r#"event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"text"}}

"#,
        );
        assert_eq!(extract_tool_name(&data), None);
    }

    #[test]
    fn test_extract_block_index() {
        let data = chunk(r#"data: {"type":"content_block_stop","index":3}"#);
        assert_eq!(extract_block_index(&data), Some(3));
    }

    #[test]
    fn test_extract_partial_json_match() {
        let data = chunk(
            r#"event: content_block_delta
data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"cmd\":\"ls\"}"}}

"#,
        );
        let result = extract_partial_json(&data, 1);
        assert!(result.is_some());
        assert!(result.unwrap().contains("cmd"));
    }

    #[test]
    fn test_extract_partial_json_wrong_index() {
        let data = chunk(
            r#"data: {"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"x"}}"#,
        );
        assert_eq!(extract_partial_json(&data, 1), None);
    }
}

//! SSE chunk parsing utilities for the HIT stream.
//!
//! Fast substring-based parsers for Anthropic SSE events.
//! All functions operate on raw `&[u8]` and avoid full JSON deserialization
//! to stay on the zero-allocation fast path for non-tool-use chunks.

use memchr::memmem;

/// Extracts the tool name from a `content_block_start` SSE chunk.
///
/// Uses `memchr::memmem` for SIMD-accelerated substring search.
/// Returns `None` if the chunk does not contain a `tool_use` content block.
pub fn extract_tool_name(bytes: &[u8]) -> Option<String> {
    memmem::find(bytes, b"\"tool_use\"")?;
    let chunk = std::str::from_utf8(bytes).ok()?;
    let marker = "\"name\":\"";
    let start = chunk.find(marker)?;
    let value_start = start + marker.len();
    let remaining = &chunk[value_start..];
    let end = remaining.find('"')?;
    Some(remaining[..end].to_string())
}

/// Extracts the block index from a `content_block_start` or `content_block_stop` chunk.
///
/// Returns `None` if no `"index":` field is found or the value is not a valid `u32`.
pub fn extract_block_index(bytes: &[u8]) -> Option<u32> {
    let chunk = std::str::from_utf8(bytes).ok()?;
    let marker = "\"index\":";
    let start = chunk.find(marker)?;
    let value_start = start + marker.len();
    let remaining = &chunk[value_start..];
    let end = remaining
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(remaining.len());
    remaining[..end].parse().ok()
}

/// Extracts the `partial_json` value from an `input_json_delta` SSE chunk.
///
/// Validates that the chunk's block index matches `target_index` before extracting.
/// Returns `None` if the chunk is not an `input_json_delta` for `target_index`,
/// or if the `partial_json` value is empty.
pub fn extract_partial_json(bytes: &[u8], target_index: u32) -> Option<String> {
    memmem::find(bytes, b"input_json_delta")?;
    if extract_block_index(bytes)? != target_index {
        return None;
    }
    let chunk = std::str::from_utf8(bytes).ok()?;
    let marker = "\"partial_json\":\"";
    let start = chunk.find(marker)?;
    let after = &chunk[start + marker.len()..];
    let mut raw = String::new();
    let mut chars = after.chars();
    loop {
        match chars.next()? {
            '"' => break,
            '\\' => match chars.next()? {
                '"' => raw.push('"'),
                '\\' => raw.push('\\'),
                'n' => raw.push('\n'),
                'r' => raw.push('\r'),
                't' => raw.push('\t'),
                c => {
                    raw.push('\\');
                    raw.push(c);
                }
            },
            c => raw.push(c),
        }
    }
    if raw.is_empty() {
        None
    } else {
        Some(raw)
    }
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

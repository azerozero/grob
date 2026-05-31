//! Salvage of leaked tool calls from OpenAI/Codex model output.
//!
//! Some OpenAI-family models — notably ChatGPT Codex (gpt-5.x) behind the
//! Responses API — occasionally emit a tool invocation as **plain text** inside
//! the assistant content instead of through the structured tool-call channel,
//! e.g. the streamed text contains:
//!
//! ```text
//! <tool_call>
//! {"name": "Bash", "arguments": {"command": "ls"}}
//! </tool_call>
//! ```
//!
//! When that happens the downstream Anthropic-API client (Claude Code, etc.)
//! sees only narrative text, never runs the tool, and the model stalls
//! believing it has no tools. This module detects those leaked blocks and lets
//! the streaming/non-streaming transforms re-emit them as real Anthropic
//! `tool_use` content blocks — the same recovery LiteLLM and claude-code-router
//! perform.
//!
//! The scan is provider-output-shaped, not client-shaped, so it works for any
//! Anthropic-API client regardless of which model name was requested.

/// Opening marker of a leaked tool call.
const OPEN: &str = "<tool_call>";
/// Closing marker of a leaked tool call.
const CLOSE: &str = "</tool_call>";
/// Tool name assigned to nameless shell-style leaks (the Codex `shell` format).
const SHELL_TOOL_NAME: &str = "Bash";

/// One item produced while scanning model text for leaked tool calls.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum SalvageEvent {
    /// A run of plain text safe to forward to the client verbatim.
    Text(String),
    /// A recovered tool call to re-emit as an Anthropic `tool_use` block.
    ToolCall(SalvagedToolCall),
}

/// A tool call recovered from leaked `<tool_call>` text.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SalvagedToolCall {
    /// Anthropic `tool_use` name.
    pub name: String,
    /// Anthropic `tool_use` input object.
    pub input: serde_json::Value,
}

/// Drains a streaming text buffer, returning complete text/tool-call events.
///
/// Consumes everything that can be safely classified and leaves the rest in
/// `buffer` for the next delta. Specifically it retains: (a) an open
/// `<tool_call>` whose closing marker has not arrived yet, and (b) a trailing
/// fragment that could be the start of a split `<tool_call>` marker. This makes
/// the scan robust to markers split across `output_text.delta` fragments.
pub(crate) fn drain_buffer(buffer: &mut String) -> Vec<SalvageEvent> {
    let mut events = Vec::new();

    loop {
        if let Some(open_idx) = buffer.find(OPEN) {
            if open_idx > 0 {
                push_text(&mut events, buffer[..open_idx].to_string());
            }

            let after_open = open_idx + OPEN.len();
            if let Some(rel_close) = buffer[after_open..].find(CLOSE) {
                let inner = &buffer[after_open..after_open + rel_close];
                match parse_tool_call(inner) {
                    Some(call) => events.push(SalvageEvent::ToolCall(call)),
                    // Unparseable block: preserve it verbatim rather than drop it.
                    None => push_text(&mut events, format!("{OPEN}{inner}{CLOSE}")),
                }
                let consumed = after_open + rel_close + CLOSE.len();
                *buffer = buffer[consumed..].to_string();
                continue;
            }

            // Open marker without a close yet — wait for more deltas.
            *buffer = buffer[open_idx..].to_string();
            return events;
        }

        // No open marker. Hold back any suffix that could begin one.
        let keep = partial_open_suffix_len(buffer);
        let flush_to = buffer.len() - keep;
        if flush_to > 0 {
            push_text(&mut events, buffer[..flush_to].to_string());
        }
        *buffer = buffer[flush_to..].to_string();
        return events;
    }
}

/// Scans a complete (non-streamed) text body for leaked tool calls.
///
/// Returns the text split into ordered text and tool-call events. When no
/// marker is present the whole body is returned as a single [`SalvageEvent::Text`].
pub(crate) fn salvage_complete(text: &str) -> Vec<SalvageEvent> {
    if !text.contains(OPEN) {
        return vec![SalvageEvent::Text(text.to_string())];
    }
    let mut buffer = text.to_string();
    let mut events = drain_buffer(&mut buffer);
    // A complete body cannot grow further, so any retained tail (an unterminated
    // marker or split-marker fragment) is just text.
    if !buffer.is_empty() {
        push_text(&mut events, buffer);
    }
    events
}

/// Appends text to `events`, coalescing with a trailing text event if present.
fn push_text(events: &mut Vec<SalvageEvent>, text: String) {
    if text.is_empty() {
        return;
    }
    if let Some(SalvageEvent::Text(last)) = events.last_mut() {
        last.push_str(&text);
    } else {
        events.push(SalvageEvent::Text(text));
    }
}

/// Returns the longest suffix length of `buffer` that is a strict prefix of [`OPEN`].
///
/// Used to hold back a trailing fragment like `"<too"` that might continue into
/// a full `<tool_call>` marker on the next delta. Markers are ASCII, so the
/// returned length always lands on a UTF-8 char boundary.
fn partial_open_suffix_len(buffer: &str) -> usize {
    let open = OPEN.as_bytes();
    let buf = buffer.as_bytes();
    let max = open.len().min(buf.len());
    (1..max)
        .rev()
        .find(|&k| buf[buf.len() - k..] == open[..k])
        .unwrap_or(0)
}

/// Parses the JSON inside a `<tool_call>` block into a [`SalvagedToolCall`].
///
/// Recognises two shapes:
/// - Canonical function call: `{"name": "X", "arguments": {…}}` (also accepts
///   `parameters`, and `arguments` as a JSON-encoded string).
/// - Nameless Codex shell call: `{"cmd"|"command": …, "workdir"?: …}` → mapped
///   to the [`SHELL_TOOL_NAME`] tool with a single `command` string.
///
/// Returns `None` when the inner text is not JSON or carries no usable call, so
/// the caller can fall back to forwarding it as plain text.
fn parse_tool_call(inner: &str) -> Option<SalvagedToolCall> {
    let value: serde_json::Value = serde_json::from_str(inner.trim()).ok()?;
    let obj = value.as_object()?;

    if let Some(name) = obj.get("name").and_then(|n| n.as_str()) {
        if !name.is_empty() {
            let input = normalize_arguments(obj.get("arguments").or_else(|| obj.get("parameters")));
            return Some(SalvagedToolCall {
                name: name.to_string(),
                input,
            });
        }
    }

    // Codex emits its native shell call without a `name`; map it to Bash so the
    // client can still run it.
    if let Some(cmd) = obj.get("cmd").or_else(|| obj.get("command")) {
        if let Some(command) = shell_command_string(cmd) {
            let full = match obj.get("workdir").and_then(|w| w.as_str()) {
                Some(dir) if !dir.is_empty() => format!("cd {} && {}", shell_quote(dir), command),
                _ => command,
            };
            return Some(SalvagedToolCall {
                name: SHELL_TOOL_NAME.to_string(),
                input: serde_json::json!({ "command": full }),
            });
        }
    }

    None
}

/// Normalizes a leaked `arguments`/`parameters` field into an input object.
fn normalize_arguments(value: Option<&serde_json::Value>) -> serde_json::Value {
    match value {
        // Some models double-encode arguments as a JSON string.
        Some(serde_json::Value::String(s)) => {
            serde_json::from_str(s).unwrap_or_else(|_| serde_json::json!({}))
        }
        Some(other) => other.clone(),
        None => serde_json::json!({}),
    }
}

/// Flattens a Codex `cmd`/`command` value into a single shell command string.
///
/// `["bash", "-lc", "<script>"]` and `["sh", "-c", "<script>"]` collapse to the
/// script itself; other arrays are space-joined; a bare string passes through.
fn shell_command_string(cmd: &serde_json::Value) -> Option<String> {
    match cmd {
        serde_json::Value::String(s) if !s.is_empty() => Some(s.clone()),
        serde_json::Value::Array(arr) => {
            let parts: Vec<&str> = arr.iter().filter_map(|x| x.as_str()).collect();
            if parts.is_empty() {
                return None;
            }
            let is_shell_wrapper = parts.len() >= 3
                && matches!(parts[0], "bash" | "sh" | "zsh")
                && matches!(parts[1], "-c" | "-lc" | "-ic");
            if is_shell_wrapper {
                Some(parts[parts.len() - 1].to_string())
            } else {
                Some(parts.join(" "))
            }
        }
        _ => None,
    }
}

/// Single-quotes a string for safe interpolation into a shell command.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drain_once(text: &str) -> Vec<SalvageEvent> {
        let mut buf = text.to_string();
        drain_buffer(&mut buf)
    }

    #[test]
    fn plain_text_passes_through() {
        assert_eq!(
            salvage_complete("just some text"),
            vec![SalvageEvent::Text("just some text".to_string())]
        );
    }

    #[test]
    fn canonical_tool_call_is_salvaged() {
        let events = salvage_complete(
            r#"before <tool_call>{"name":"Bash","arguments":{"command":"ls"}}</tool_call> after"#,
        );
        assert_eq!(
            events,
            vec![
                SalvageEvent::Text("before ".to_string()),
                SalvageEvent::ToolCall(SalvagedToolCall {
                    name: "Bash".to_string(),
                    input: serde_json::json!({ "command": "ls" }),
                }),
                SalvageEvent::Text(" after".to_string()),
            ]
        );
    }

    #[test]
    fn arguments_as_json_string_are_decoded() {
        let events = salvage_complete(
            r#"<tool_call>{"name":"Read","arguments":"{\"path\":\"/tmp/x\"}"}</tool_call>"#,
        );
        assert_eq!(
            events,
            vec![SalvageEvent::ToolCall(SalvagedToolCall {
                name: "Read".to_string(),
                input: serde_json::json!({ "path": "/tmp/x" }),
            })]
        );
    }

    #[test]
    fn nameless_codex_shell_call_maps_to_bash() {
        let events = salvage_complete(
            r#"<tool_call>{"cmd":["bash","-lc","pwd && ls"],"workdir":"/repo"}</tool_call>"#,
        );
        assert_eq!(
            events,
            vec![SalvageEvent::ToolCall(SalvagedToolCall {
                name: "Bash".to_string(),
                input: serde_json::json!({ "command": "cd '/repo' && pwd && ls" }),
            })]
        );
    }

    #[test]
    fn marker_split_across_deltas_is_buffered() {
        // Simulate three streamed fragments that split the open marker and JSON.
        let mut buf = String::new();
        let mut all = Vec::new();

        buf.push_str("hello <too");
        all.extend(drain_buffer(&mut buf));
        // The partial marker must be held back, only "hello " flushed.
        assert_eq!(all, vec![SalvageEvent::Text("hello ".to_string())]);

        buf.push_str(r#"l_call>{"name":"Bash","#);
        all.extend(drain_buffer(&mut buf));
        // Open seen but not closed yet — nothing new emitted.
        assert_eq!(all, vec![SalvageEvent::Text("hello ".to_string())]);

        buf.push_str(r#""arguments":{"command":"ls"}}</tool_call>done"#);
        all.extend(drain_buffer(&mut buf));
        assert_eq!(
            all,
            vec![
                SalvageEvent::Text("hello ".to_string()),
                SalvageEvent::ToolCall(SalvagedToolCall {
                    name: "Bash".to_string(),
                    input: serde_json::json!({ "command": "ls" }),
                }),
                SalvageEvent::Text("done".to_string()),
            ]
        );
        assert!(buf.is_empty());
    }

    #[test]
    fn unparseable_block_is_kept_as_text() {
        let events = drain_once("<tool_call>not json</tool_call>");
        assert_eq!(
            events,
            vec![SalvageEvent::Text(
                "<tool_call>not json</tool_call>".to_string()
            )]
        );
    }

    #[test]
    fn unterminated_marker_is_retained_in_buffer() {
        let mut buf = r#"text <tool_call>{"name":"Bash""#.to_string();
        let events = drain_buffer(&mut buf);
        assert_eq!(events, vec![SalvageEvent::Text("text ".to_string())]);
        assert_eq!(buf, r#"<tool_call>{"name":"Bash""#);
    }

    #[test]
    fn multibyte_text_before_partial_marker_is_safe() {
        // Ensure suffix retention does not split a multibyte char.
        let mut buf = "café <".to_string();
        let events = drain_buffer(&mut buf);
        assert_eq!(events, vec![SalvageEvent::Text("café ".to_string())]);
        assert_eq!(buf, "<");
    }

    #[test]
    fn fenced_codex_leak_is_recovered() {
        // The exact shape observed from gpt-5.5: a markdown bash fence wrapping a
        // nameless shell tool_call.
        let leak = "```bash\npwd\n<tool_call>\n{\"cmd\":[\"bash\",\"-lc\",\"pwd && git log\"],\"workdir\":\"/Users/ludwig/workspace/reti\"}\n</tool_call>\n```";
        let events = salvage_complete(leak);
        let tool = events
            .iter()
            .find_map(|e| match e {
                SalvageEvent::ToolCall(c) => Some(c),
                _ => None,
            })
            .expect("a tool call should be recovered");
        assert_eq!(tool.name, "Bash");
        assert_eq!(
            tool.input,
            serde_json::json!({ "command": "cd '/Users/ludwig/workspace/reti' && pwd && git log" })
        );
    }
}

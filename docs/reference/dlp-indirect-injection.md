# DLP Indirect Injection Detection

Grob scans LLM responses and `tool_result` blocks for indirect prompt injection attempts. This closes the gap where hostile instructions embedded in tool outputs (web pages, file contents, command output) can manipulate the LLM.

See [ADR-0015](../decisions/0015-indirect-prompt-injection-coverage.md) for the design rationale.

## Configuration

```toml
[dlp.prompt_injection]
enabled = true
action = "block"                # action for direct injection (user input)
scan_responses = true           # scan LLM response text
scan_tool_results = true        # scan tool_result content blocks
response_action = "log"         # action for indirect injection: log | block | redact
```

### Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `scan_responses` | bool | `true` | Scans LLM response text for injection patterns. |
| `scan_tool_results` | bool | `true` | Scans `tool_result` content blocks before the LLM processes them. |
| `response_action` | string | `"log"` | Action on indirect injection detection. `"log"` emits a warning without blocking. `"block"` terminates the request/stream. `"redact"` behaves like `"log"` (warn only). |

### Action semantics

| Action | Behavior |
|--------|----------|
| `log` | Emits a structured audit log entry and a `grob_dlp_detections_total` metric with `type=indirect_injection`. The response or tool result is passed through unchanged. **Recommended for initial deployment.** |
| `block` | Rejects the request (for `tool_result` blocks) or terminates the SSE stream (for responses) with a `DlpBlockError`. |
| `redact` | Same as `log` (warn only). Reserved for future per-pattern redaction. |

## Scan points

```
                    ┌─────────────────────┐
                    │   User request      │
                    │                     │
  tool_result ──────┤  scan_tool_results  │──► block or warn
  blocks            │                     │
                    └─────────┬───────────┘
                              │
                              ▼
                    ┌─────────────────────┐
                    │   Provider call      │
                    └─────────┬───────────┘
                              │
                              ▼
                    ┌─────────────────────┐
                    │   LLM response      │
                    │                     │
  response text ────┤  scan_responses     │──► block (stream) or warn
                    │                     │
                    └─────────────────────┘
```

### Tool result scanning

Runs during `sanitize_request_checked()`, after the direct injection scan and before the request reaches any provider. Extracts text from all `tool_result` content blocks (both `Text(String)` and `Blocks(Vec<ToolResultBlock>)` variants) and scans them with the indirect injection detector.

### Response scanning

Runs during `sanitize_response_text_reported()` as step 5, after URL exfiltration scanning. For streaming responses, the accumulated buffer is checked after each SSE chunk.

## Pattern engine

Indirect injection reuses the same multilingual pattern set as direct injection scanning (28 languages + obfuscation resistance). The normalization pipeline applies:

1. Zero-width character stripping
2. NFKC Unicode normalization + homoglyph mapping
3. Leet speak decoding (aggressive pass)

## Metrics

| Metric | Labels | Description |
|--------|--------|-------------|
| `grob_dlp_detections_total` | `type=indirect_injection`, `rule=<pattern>`, `action=<log\|block>` | Counter incremented per detection. |
| `grob_dlp_stream_blocked_total` | — | Counter incremented when a streaming response is terminated due to indirect injection block. |

## Audit logging

Each detection emits a structured log entry at `WARN` level to the `grob::dlp::audit` target:

```
event=indirect_injection_detected pattern=<name> action=<action> matched_text_len=<n>
```

## Interaction with other DLP features

- **Direct injection scanning** (`action`) is independent of indirect scanning (`response_action`). Both can be configured separately.
- **URL exfiltration** runs before indirect injection scanning on responses.
- **Pledge filter** removes dangerous tools at the structural level; indirect injection scanning inspects content returned by tools that are kept.
- **Secret scanning and PII detection** run on both requests and responses regardless of injection scanning settings.

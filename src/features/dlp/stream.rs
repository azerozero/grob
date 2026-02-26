use super::DlpEngine;
use bytes::Bytes;
use futures::stream::Stream;
use memchr::memmem;
use pin_project::pin_project;
use std::borrow::Cow;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

/// Maximum canary tokens per stream before circuit-breaking to [REDACTED].
const MAX_CANARIES_PER_STREAM: usize = 20;

/// Maximum SPRT buffer size (4 KB). Older text is slid out.
const SPRT_BUFFER_CAP: usize = 4096;

/// Token-length EMA tracker. When the exponential moving average of
/// per-delta text lengths stays above `THRESHOLD`, the DFA scan is skipped
/// because long tokens are overwhelmingly natural prose, not secrets.
struct TokenLengthEma {
    ema: f32,
    alpha: f32,
}

const EMA_THRESHOLD: f32 = 2.5;

impl TokenLengthEma {
    fn new() -> Self {
        Self {
            ema: 0.0,
            alpha: 0.2, // window of ~5 tokens
        }
    }

    /// Update with a new token length. Returns `true` if the text is suspect
    /// (short tokens → likely BPE fragments that could form a secret).
    /// Checks EMA *before* updating so the first token (EMA=0) always triggers a scan.
    fn update(&mut self, len: usize) -> bool {
        let suspect = self.ema < EMA_THRESHOLD;
        self.ema = self.alpha * len as f32 + (1.0 - self.alpha) * self.ema;
        suspect
    }
}

/// Stream adapter that intercepts SSE events and applies DLP scanning/replacement.
///
/// Performance design:
/// - Zero-copy passthrough for chunks with no `content_block_delta` events
/// - SIMD-accelerated `memchr::memmem` for byte-level substring search
/// - Fast substring extraction of `"text":"..."` without full JSON parse
/// - Token-length EMA pre-filter skips DFA for normal prose
/// - Only allocates when DLP actually modifies content
///
/// Correctness:
/// - End-of-stream DFA scan on accumulated `buffer` catches cross-chunk secrets
/// - Canary circuit breaker (max 20 per stream) prevents canary flooding
/// - SPRT buffer capped at 4KB to prevent OOM
#[pin_project]
pub struct DlpStream<S> {
    #[pin]
    inner: S,
    engine: Arc<DlpEngine>,
    /// Accumulated full response text for end-of-stream cross-chunk scan.
    buffer: String,
    /// Bounded SPRT entropy buffer (max SPRT_BUFFER_CAP bytes).
    sprt_buffer: String,
    /// Canary circuit breaker: counts canary tokens emitted in this stream.
    canary_count: usize,
    /// Token-length EMA for skipping DFA on long (prose) tokens.
    token_ema: TokenLengthEma,
    /// Set to true when URL exfil block terminates the stream.
    blocked: bool,
}

impl<S> DlpStream<S>
where
    S: Stream<Item = Result<Bytes, crate::providers::error::ProviderError>> + Send,
{
    pub fn new(inner: S, engine: Arc<DlpEngine>) -> Self {
        Self {
            inner,
            engine,
            buffer: String::new(),
            sprt_buffer: String::new(),
            canary_count: 0,
            token_ema: TokenLengthEma::new(),
            blocked: false,
        }
    }
}

impl<S> Stream for DlpStream<S>
where
    S: Stream<Item = Result<Bytes, crate::providers::error::ProviderError>> + Send,
{
    type Item = Result<Bytes, crate::providers::error::ProviderError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();

        // If we've already blocked, terminate the stream
        if *this.blocked {
            return Poll::Ready(None);
        }

        match this.inner.poll_next(cx) {
            Poll::Ready(Some(Ok(bytes))) => {
                // Fast path: SIMD check if chunk contains content_block_delta
                if memmem::find(&bytes, b"content_block_delta").is_none() {
                    return Poll::Ready(Some(Ok(bytes)));
                }

                // Need to process — convert to string
                let chunk = String::from_utf8_lossy(&bytes);
                let ctx = &mut StreamContext {
                    engine: this.engine,
                    buffer: this.buffer,
                    sprt_buffer: this.sprt_buffer,
                    canary_count: this.canary_count,
                    token_ema: this.token_ema,
                };
                let result = match process_sse_chunk(&chunk, ctx) {
                    Cow::Borrowed(_) => Poll::Ready(Some(Ok(bytes))),
                    Cow::Owned(modified) => Poll::Ready(Some(Ok(Bytes::from(modified)))),
                };

                // Check for URL exfil block on accumulated buffer
                if let Err(block_err) = this.engine.check_response_url_exfil(this.buffer) {
                    *this.blocked = true;
                    tracing::warn!("DLP stream blocked: {}", block_err);
                    metrics::counter!("grob_dlp_stream_blocked_total").increment(1);
                    // Emit error SSE event then terminate
                    let error_event = format!(
                        "event: error\ndata: {{\"type\":\"dlp_block\",\"message\":\"{}\"}}\n\n",
                        block_err.to_string().replace('"', "\\\"")
                    );
                    return Poll::Ready(Some(Ok(Bytes::from(error_event))));
                }

                result
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => {
                // Stream ended — run end-of-stream scans
                if !this.buffer.is_empty() {
                    // Phase 2: cross-chunk DFA + name deanonymization scan
                    this.engine.scan_end_of_stream(this.buffer);
                    // Async SPRT entropy scan on accumulated text
                    this.engine.scan_entropy_async(std::mem::take(this.buffer));
                }
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Mutable context threaded through SSE chunk processing.
struct StreamContext<'a> {
    engine: &'a Arc<DlpEngine>,
    buffer: &'a mut String,
    sprt_buffer: &'a mut String,
    canary_count: &'a mut usize,
    token_ema: &'a mut TokenLengthEma,
}

/// Process an SSE chunk, applying DLP transformations to text content.
/// Returns Cow::Borrowed if no modifications were needed.
fn process_sse_chunk<'a>(chunk: &'a str, ctx: &mut StreamContext<'_>) -> Cow<'a, str> {
    let mut output: Option<String> = None;
    let mut lines = chunk.split('\n').peekable();
    let mut current_event_is_delta = false;
    let mut output_pos = 0;

    while let Some(line) = lines.next() {
        if let Some(event_type) = line.strip_prefix("event: ") {
            current_event_is_delta = event_type.trim() == "content_block_delta";
        } else if line.starts_with("data: ") && current_event_is_delta {
            let data = &line[6..];
            if let Some(transformed) = transform_delta_data(data, ctx) {
                let out = output.get_or_insert_with(|| {
                    let mut s = String::with_capacity(chunk.len());
                    s.push_str(&chunk[..output_pos]);
                    s
                });
                out.push_str("data: ");
                out.push_str(&transformed);
                out.push('\n');

                let line_end = output_pos + line.len();
                output_pos = if lines.peek().is_some() {
                    line_end + 1
                } else {
                    line_end
                };
                continue;
            }
        } else if line.trim().is_empty() {
            current_event_is_delta = false;
        }

        if let Some(ref mut out) = output {
            out.push_str(line);
            if lines.peek().is_some() {
                out.push('\n');
            }
        }

        output_pos += line.len();
        if lines.peek().is_some() {
            output_pos += 1;
        }
    }

    match output {
        Some(s) => Cow::Owned(s),
        None => Cow::Borrowed(chunk),
    }
}

/// Transform a `content_block_delta` data payload, applying DLP to the text field.
/// Returns Some(modified_json_string) only if DLP actually changed the text.
fn transform_delta_data(data: &str, ctx: &mut StreamContext<'_>) -> Option<String> {
    if !data.contains("text_delta") {
        return None;
    }

    // Try fast extraction first
    if let Some(text_value) = extract_text_field(data) {
        // EMA pre-filter: skip DFA for long prose tokens
        let suspect = ctx.token_ema.update(text_value.len());
        if !suspect {
            accumulate_text(text_value, ctx);
            return None;
        }

        let sanitized = sanitize_with_circuit_breaker(text_value, ctx.engine, ctx.canary_count);
        if let Cow::Owned(ref new_text) = sanitized {
            // Buffer the sanitized text so end-of-stream scan doesn't re-detect
            accumulate_text(new_text, ctx);
            let mut json: serde_json::Value = serde_json::from_str(data).ok()?;
            let delta = json.get_mut("delta")?;
            if let Some(text_val) = delta.get_mut("text") {
                *text_val = serde_json::Value::String(new_text.clone());
            }
            return serde_json::to_string(&json).ok();
        }
        // No modification — buffer original text
        accumulate_text(text_value, ctx);
    } else {
        // Fallback: full JSON parse for edge cases
        let mut json: serde_json::Value = serde_json::from_str(data).ok()?;
        let delta = json.get_mut("delta")?;
        let delta_type = delta.get("type")?.as_str()?;
        if delta_type == "text_delta" {
            if let Some(text_val) = delta.get_mut("text") {
                if let Some(text) = text_val.as_str() {
                    let suspect = ctx.token_ema.update(text.len());
                    if !suspect {
                        accumulate_text(text, ctx);
                        return None;
                    }

                    let sanitized =
                        sanitize_with_circuit_breaker(text, ctx.engine, ctx.canary_count);
                    if let Cow::Owned(ref new_text) = sanitized {
                        accumulate_text(new_text, ctx);
                        *text_val = serde_json::Value::String(new_text.clone());
                        return serde_json::to_string(&json).ok();
                    }
                    accumulate_text(text, ctx);
                }
            }
        }
    }

    None
}

/// Accumulate text into both the cross-chunk buffer and the bounded SPRT buffer.
fn accumulate_text(text: &str, ctx: &mut StreamContext<'_>) {
    // Full buffer for cross-chunk scan (unbounded is OK — it's the full response text
    // that we'd scan with SPRT anyway; capped by response length)
    ctx.buffer.push_str(text);

    // Bounded SPRT buffer: slide window when over cap
    ctx.sprt_buffer.push_str(text);
    if ctx.sprt_buffer.len() > SPRT_BUFFER_CAP {
        let excess = ctx.sprt_buffer.len() - SPRT_BUFFER_CAP;
        // Find the next char boundary after `excess` to avoid splitting a UTF-8 sequence
        let drain_to = ctx.sprt_buffer.ceil_char_boundary(excess);
        ctx.sprt_buffer.drain(..drain_to);
    }
}

/// Apply DLP sanitization with canary circuit breaker.
/// After MAX_CANARIES_PER_STREAM secret detections, force-redact instead of canary.
/// Only counts actual secret hits (not name deanonymizations).
fn sanitize_with_circuit_breaker<'a>(
    text: &'a str,
    engine: &Arc<DlpEngine>,
    canary_count: &mut usize,
) -> Cow<'a, str> {
    if *canary_count >= MAX_CANARIES_PER_STREAM {
        // Circuit breaker active: use redact-only mode
        return redact_only(text, engine);
    }

    // Check if this text contains a secret (independent of name deanonymization)
    let has_secret = !engine.scanner.is_empty()
        && engine.scanner.might_contain_secret(text)
        && !engine.scanner.scan(text).is_empty();

    let result = engine.sanitize_response_text(text);
    if has_secret && matches!(result, Cow::Owned(_)) {
        *canary_count += 1;
        if *canary_count == MAX_CANARIES_PER_STREAM {
            tracing::warn!(
                "DLP canary circuit breaker: {} secret detections, switching to [REDACTED]",
                MAX_CANARIES_PER_STREAM
            );
            metrics::counter!("grob_dlp_circuit_breaker_total").increment(1);
        }
    }
    result
}

/// Redact-only mode: replace any detected secret with [REDACTED] instead of canary.
fn redact_only<'a>(text: &'a str, engine: &Arc<DlpEngine>) -> Cow<'a, str> {
    let mut modified: Option<String> = None;

    // Deanonymize names (always needed)
    if !engine.anonymizer.is_empty() {
        let current = modified.as_deref().unwrap_or(text);
        if let Some(deanonymized) = engine.anonymizer.deanonymize_if_match(current) {
            modified = Some(deanonymized);
        }
    }

    // Redact secrets (force [REDACTED] regardless of rule action)
    if !engine.scanner.is_empty() {
        let current = modified.as_deref().unwrap_or(text);
        if engine.scanner.might_contain_secret(current) {
            let matches = engine.scanner.scan(current);
            if !matches.is_empty() {
                let mut result = String::with_capacity(current.len());
                let mut last_end = 0;
                for m in &matches {
                    if m.start < last_end {
                        continue;
                    }
                    result.push_str(&current[last_end..m.start]);
                    result.push_str("[REDACTED]");
                    last_end = m.end;
                }
                result.push_str(&current[last_end..]);
                modified = Some(result);
            }
        }
    }

    match modified {
        Some(s) => Cow::Owned(s),
        None => Cow::Borrowed(text),
    }
}

/// Fast extraction of the "text" field value from a JSON string.
/// Handles simple cases without JSON escapes. Returns None if the structure
/// is too complex (escaped quotes, nested objects) — caller falls back to serde.
fn extract_text_field(json: &str) -> Option<&str> {
    let marker = "\"text\":\"";
    let start = json.find(marker)?;
    let value_start = start + marker.len();

    let remaining = &json[value_start..];
    let mut end = 0;
    let bytes = remaining.as_bytes();
    while end < bytes.len() {
        match bytes[end] {
            b'"' => {
                return Some(&remaining[..end]);
            }
            b'\\' => {
                return None;
            }
            _ => end += 1,
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::dlp::config::*;

    fn test_engine() -> Arc<DlpEngine> {
        let config = DlpConfig {
            enabled: true,
            scan_input: true,
            scan_output: true,
            rules_file: String::new(),
            secrets: vec![SecretRule {
                name: "github_token".into(),
                prefix: "ghp_".into(),
                pattern: "ghp_[A-Za-z0-9]{36}".into(),
                action: SecretAction::Canary,
            }],
            custom_prefixes: vec![],
            names: vec![],
            entropy: EntropyConfig::default(),
            pii: Default::default(),
            no_builtins: true,
            enable_sessions: false,
            url_exfil: Default::default(),
            prompt_injection: Default::default(),
            signed_config: Default::default(),
        };
        DlpEngine::from_config(config).unwrap()
    }

    fn make_ctx<'a>(
        engine: &'a Arc<DlpEngine>,
        buffer: &'a mut String,
        sprt_buffer: &'a mut String,
        canary_count: &'a mut usize,
        token_ema: &'a mut TokenLengthEma,
    ) -> StreamContext<'a> {
        StreamContext {
            engine,
            buffer,
            sprt_buffer,
            canary_count,
            token_ema,
        }
    }

    #[test]
    fn test_passthrough_non_delta() {
        let engine = test_engine();
        let chunk = "event: message_start\ndata: {\"type\":\"message_start\"}\n\n";
        let mut buf = String::new();
        let mut sprt = String::new();
        let mut cc = 0;
        let mut ema = TokenLengthEma::new();
        let mut ctx = make_ctx(&engine, &mut buf, &mut sprt, &mut cc, &mut ema);
        let result = process_sse_chunk(chunk, &mut ctx);
        assert!(matches!(result, Cow::Borrowed(_)));
    }

    #[test]
    fn test_transform_text_delta_with_secret() {
        let engine = test_engine();
        let data = r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"token: ghp_abcdefghijklmnopqrstuvwxyz1234567890"}}"#;
        let chunk = format!("event: content_block_delta\ndata: {}\n\n", data);
        let mut buf = String::new();
        let mut sprt = String::new();
        let mut cc = 0;
        let mut ema = TokenLengthEma::new();
        let mut ctx = make_ctx(&engine, &mut buf, &mut sprt, &mut cc, &mut ema);
        let result = process_sse_chunk(&chunk, &mut ctx);
        assert!(matches!(result, Cow::Owned(_)));
        assert!(!result.contains("ghp_abcdefghijklmnopqrstuvwxyz1234567890"));
        assert!(result.contains("ghp_~CANARY"));
    }

    #[test]
    fn test_buffer_accumulates() {
        let engine = test_engine();
        let data1 = r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello "}}"#;
        let data2 = r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"world"}}"#;
        let chunk1 = format!("event: content_block_delta\ndata: {}\n\n", data1);
        let chunk2 = format!("event: content_block_delta\ndata: {}\n\n", data2);

        let mut buf = String::new();
        let mut sprt = String::new();
        let mut cc = 0;
        let mut ema = TokenLengthEma::new();
        let mut ctx = make_ctx(&engine, &mut buf, &mut sprt, &mut cc, &mut ema);
        process_sse_chunk(&chunk1, &mut ctx);
        process_sse_chunk(&chunk2, &mut ctx);
        assert_eq!(buf, "Hello world");
    }

    #[test]
    fn test_clean_delta_is_passthrough() {
        let engine = test_engine();
        let data = r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello world"}}"#;
        let chunk = format!("event: content_block_delta\ndata: {}\n\n", data);
        let mut buf = String::new();
        let mut sprt = String::new();
        let mut cc = 0;
        let mut ema = TokenLengthEma::new();
        let mut ctx = make_ctx(&engine, &mut buf, &mut sprt, &mut cc, &mut ema);
        let result = process_sse_chunk(&chunk, &mut ctx);
        assert!(matches!(result, Cow::Borrowed(_)));
        assert_eq!(buf, "Hello world");
    }

    #[test]
    fn test_extract_text_field_simple() {
        let json = r#"{"type":"content_block_delta","delta":{"type":"text_delta","text":"hello"}}"#;
        assert_eq!(extract_text_field(json), Some("hello"));
    }

    #[test]
    fn test_extract_text_field_with_escapes_bails() {
        let json = r#"{"delta":{"type":"text_delta","text":"hello \"world\""}}"#;
        assert!(extract_text_field(json).is_none());
    }

    #[test]
    fn test_memchr_memmem_find() {
        // memmem::find(haystack, needle) → Option<usize>
        assert!(memmem::find(b"content_block_delta", b"delta").is_some());
        assert!(memmem::find(b"message_start", b"delta").is_none());
        assert!(memmem::find(b"content_block_delta", b"content_block_delta").is_some());
        assert!(memmem::find(b"xyzcontentxyz", b"content").is_some());
        assert!(memmem::find(b"short", b"long_needle").is_none());
    }

    #[test]
    fn test_zero_copy_no_delta_chunk() {
        let bytes = Bytes::from("event: message_start\ndata: {}\n\n");
        assert!(memmem::find(&bytes, b"content_block_delta").is_none());
    }

    #[test]
    fn test_sprt_buffer_bounded() {
        let engine = test_engine();
        let mut buf = String::new();
        let mut sprt = String::new();
        let mut cc = 0;
        let mut ema = TokenLengthEma::new();
        let mut ctx = make_ctx(&engine, &mut buf, &mut sprt, &mut cc, &mut ema);

        // Push > 4KB of text through the SPRT buffer
        let big_text = "A".repeat(5000);
        accumulate_text(&big_text, &mut ctx);
        assert!(
            sprt.len() <= SPRT_BUFFER_CAP,
            "SPRT buffer should be capped at {} but was {}",
            SPRT_BUFFER_CAP,
            sprt.len()
        );
        // Full buffer should have all text
        assert_eq!(buf.len(), 5000);
    }

    #[test]
    fn test_canary_rate_limit() {
        let config = DlpConfig {
            enabled: true,
            scan_input: true,
            scan_output: true,
            rules_file: String::new(),
            no_builtins: true,
            secrets: vec![SecretRule {
                name: "github_token".into(),
                prefix: "ghp_".into(),
                pattern: "ghp_[A-Za-z0-9]{36}".into(),
                action: SecretAction::Canary,
            }],
            custom_prefixes: vec![],
            names: vec![],
            entropy: EntropyConfig::default(),
            pii: Default::default(),
            enable_sessions: false,
            url_exfil: Default::default(),
            prompt_injection: Default::default(),
            signed_config: Default::default(),
        };
        let engine = DlpEngine::from_config(config).unwrap();
        let mut canary_count: usize = 0;

        let secret = "ghp_abcdefghijklmnopqrstuvwxyz1234567890";

        // First MAX_CANARIES_PER_STREAM should produce canaries
        for _ in 0..MAX_CANARIES_PER_STREAM {
            let result = sanitize_with_circuit_breaker(secret, &engine, &mut canary_count);
            assert!(
                result.contains("~CANARY"),
                "Should produce canary before limit"
            );
        }

        assert_eq!(canary_count, MAX_CANARIES_PER_STREAM);

        // 21st should get [REDACTED] instead
        let result = sanitize_with_circuit_breaker(secret, &engine, &mut canary_count);
        assert!(
            result.contains("[REDACTED]"),
            "Should get [REDACTED] after circuit breaker"
        );
        assert!(
            !result.contains("~CANARY"),
            "Should NOT get canary after circuit breaker"
        );
    }

    #[test]
    fn test_token_ema_filter() {
        let mut ema = TokenLengthEma::new();

        // EMA starts at 0.0, first call always suspect (checks before update)
        assert!(ema.update(1)); // check 0.0 < 2.5 = true, then ema → 0.2
        assert!(ema.update(2)); // check 0.2 < 2.5 = true, then ema → 0.56
        assert!(ema.update(1)); // check 0.56 < 2.5 = true, then ema → 0.648

        // Feed long tokens — EMA rises above threshold
        for _ in 0..15 {
            ema.update(20);
        }
        // After many long tokens, EMA should be well above 2.5
        assert!(
            !ema.update(20),
            "Long tokens should not be suspect (EMA > 2.5)"
        );

        // Feed short tokens again — EMA drops back
        for _ in 0..20 {
            ema.update(1);
        }
        assert!(
            ema.update(1),
            "After many short tokens, should be suspect again"
        );
    }

    #[test]
    fn test_cross_chunk_secret_detection() {
        // Simulate a secret split across two SSE deltas
        let config = DlpConfig {
            enabled: true,
            scan_input: true,
            scan_output: true,
            rules_file: String::new(),
            no_builtins: true,
            secrets: vec![SecretRule {
                name: "github_token".into(),
                prefix: "ghp_".into(),
                pattern: "ghp_[A-Za-z0-9]{36}".into(),
                action: SecretAction::Canary,
            }],
            custom_prefixes: vec![],
            names: vec![],
            entropy: EntropyConfig::default(),
            pii: Default::default(),
            enable_sessions: false,
            url_exfil: Default::default(),
            prompt_injection: Default::default(),
            signed_config: Default::default(),
        };
        let engine = DlpEngine::from_config(config).unwrap();

        // Delta 1: first half of secret
        let part1 = "ghp_abcdefghijklmn";
        // Delta 2: second half
        let part2 = "opqrstuvwxyz1234567890";

        // Per-delta scan won't catch either half individually
        let r1 = engine.sanitize_response_text(part1);
        let r2 = engine.sanitize_response_text(part2);
        // Neither half alone matches the full pattern
        assert!(
            matches!(r1, Cow::Borrowed(_)),
            "First half alone should not match"
        );
        assert!(
            matches!(r2, Cow::Borrowed(_)),
            "Second half alone should not match"
        );

        // But the accumulated buffer (full text) DOES match
        let full_text = format!("{}{}", part1, part2);
        assert!(
            engine.scanner.might_contain_secret(&full_text),
            "Full text should trigger prefix check"
        );
        let matches = engine.scanner.scan(&full_text);
        assert_eq!(
            matches.len(),
            1,
            "End-of-stream scan should catch the cross-chunk secret"
        );

        // scan_end_of_stream would emit the alert (we just verify the scan works)
        engine.scan_end_of_stream(&full_text);
    }
}

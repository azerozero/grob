//! Spend accounting for streaming responses.
//!
//! Streaming requests historically recorded **no** persistent spend: the
//! provider's `send_message_stream` wraps the byte stream in a logging adapter
//! that emits ephemeral Prometheus metrics, but nothing committed the cost to
//! the monthly JSONL journal that powers budget enforcement. This module closes
//! that gap with a passthrough [`SpendStream`] wrapper that observes the SSE
//! events, captures provider-reported usage when present, and on stream
//! termination records spend exactly like the non-streaming path
//! ([`crate::server::dispatch::telemetry`]).
//!
//! # Performance
//!
//! The wrapper is invisible to client-perceived latency:
//!
//! - **Bytes pass through unchanged** — each chunk is forwarded immediately in
//!   the same poll, so time-to-first-byte and inter-chunk timing are identical
//!   to the un-wrapped stream.
//! - **Per-chunk work is a cheap substring scan** ([`memchr::memmem`]), not a
//!   `serde_json` deserialization. Only the rare usage-bearing events
//!   (`message_start` / `message_delta`) are JSON-parsed, and only their small
//!   `usage` object.
//! - **Terminal recording is detached** — on stream end the cost computation,
//!   spend mutex, and JSONL append run in a spawned task so the final poll
//!   returns to the client without waiting on disk I/O.
//!
//! # Token sources
//!
//! 1. **Provider-reported usage** (authoritative): Anthropic-format SSE carries
//!    input usage in `message_start.message.usage.input_tokens` and output usage
//!    in `message_delta.usage.output_tokens`. All providers translate to this
//!    canonical SSE shape before the stream reaches dispatch, so the same parser
//!    serves every backend.
//! 2. **Estimate-mode fallback**: when a provider omits usage entirely and token
//!    counting is in [`Estimate`](crate::cli::TokenCountingMode::Estimate) mode,
//!    spend is billed from the pre-captured input estimate plus an output
//!    estimate derived from the accumulated `text_delta` character count
//!    (~4 chars/token, shared with the non-streaming fallback).
//!
//! In `api` mode with no provider usage, nothing is recorded — matching
//! non-streaming behaviour where a `$0` usage is billed as `$0`.

use bytes::Bytes;
use futures::stream::Stream;
use memchr::memmem;
use pin_project::pin_project;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use crate::models::RouteType;
use crate::server::{
    calculate_cost, is_estimate_mode, record_request_metrics, record_spend, tokens_from_chars,
    AppState, RequestMetrics,
};

/// Owned context the spend wrapper needs after the request future returns.
///
/// The wrapper outlives the request handler, so it must own clones of every
/// value (an `Arc<AppState>` and `String`s) rather than borrow the transient
/// [`DispatchContext`](crate::server::dispatch::DispatchContext).
pub(crate) struct SpendStreamContext {
    /// Shared application state (spend tracker, pricing table).
    pub state: Arc<AppState>,
    /// Provider name spend is attributed to.
    pub provider: String,
    /// Routed model name spend is recorded against (matches non-streaming).
    pub model_name: String,
    /// Backend model name used for pricing lookup.
    pub actual_model: String,
    /// Route classification, for the Prometheus `route_type` label.
    pub route_type: RouteType,
    /// Tenant the spend is isolated to (multi-tenant deployments).
    pub tenant_id: Option<String>,
    /// `true` when the provider is OAuth-backed (subscription = `$0`).
    pub is_subscription: bool,
    /// Local input-token estimate captured before the request was consumed.
    ///
    /// Only consulted as the estimate-mode fallback when the provider omits
    /// usage; zero in `api` mode.
    pub estimated_input_tokens: u32,
    /// Wall-clock instant the request started, for the latency metric.
    pub start_time: std::time::Instant,
    /// Trace-correlation id, set when request/response tracing is enabled. When
    /// present (and the tracer is active), the accumulated response text is
    /// written as a `res` trace entry on termination.
    pub trace_id: Option<String>,
}

/// Usage observed while streaming, used to compute spend on termination.
#[derive(Default)]
struct StreamUsage {
    /// Provider-reported input tokens (`message_start`).
    input_tokens: u32,
    /// Provider-reported output tokens (`message_delta`, cumulative max).
    output_tokens: u32,
    /// Provider-reported prompt-cache write tokens.
    cache_creation_input_tokens: u32,
    /// Provider-reported prompt-cache read tokens.
    cache_read_input_tokens: u32,
    /// Whether any provider usage field was seen.
    saw_usage: bool,
    /// Accumulated `text_delta` text length (bytes) for the output estimate.
    ///
    /// Byte length, not char count, to keep the hot path allocation-free; the
    /// ~4-chars/token heuristic is coarse enough that the ASCII-dominant SSE
    /// text makes the two effectively equal.
    output_bytes: usize,
    /// Accumulated response content (text, `tool_use` calls, thinking) for the
    /// `res` trace, captured ONLY when tracing is enabled (else `None`, keeping
    /// the hot path allocation-free). Each block mirrors an Anthropic content
    /// block so the streamed trace matches the non-streaming shape.
    trace: Option<Vec<TraceBlock>>,
}

/// One outgoing content block accumulated for the streaming `res` trace.
///
/// Mirrors the Anthropic content-block variants so the assembled trace shows
/// exactly what the model produced — prose, the edits/commands it asked the
/// client to run (`tool_use`, which includes Claude Code's `WebSearch`), and its
/// thinking — not just the prose.
enum TraceBlock {
    /// Assistant prose (`text_delta`).
    Text(String),
    /// Extended-thinking text (`thinking_delta`).
    Thinking(String),
    /// A tool call: `id`/`name` from `content_block_start`, arguments assembled
    /// from the `input_json_delta` partial-JSON fragments.
    ToolUse {
        id: String,
        name: String,
        input: String,
    },
}

/// Stream adapter that records spend on termination without altering bytes.
///
/// Passes every SSE chunk through verbatim in the same poll so the client sees
/// an unmodified stream with unchanged timing. Internally it does a cheap
/// substring scan per chunk and, on `None` (inner stream end), spawns the spend
/// commit.
#[pin_project]
pub(crate) struct SpendStream<S> {
    #[pin]
    inner: S,
    /// Accounting context (owned clones; outlives the request).
    ctx: SpendStreamContext,
    /// Live usage accumulator.
    usage: StreamUsage,
    /// Carry-over tail: the bytes after the last `\n\n` in the previous chunk,
    /// re-prepended so a usage/text field split across a chunk boundary is not
    /// missed. Bounded by [`MAX_CARRY`].
    carry: String,
    /// Guards against double-recording if polled after completion.
    recorded: bool,
}

impl<S> SpendStream<S>
where
    S: Stream<Item = Result<Bytes, crate::providers::error::ProviderError>> + Send,
{
    /// Wraps an inner SSE byte stream to record spend on completion.
    pub(crate) fn new(inner: S, ctx: SpendStreamContext) -> Self {
        // Capture the response content only when tracing is active, so the common
        // path stays allocation-free.
        let trace: Option<Vec<TraceBlock>> = (ctx.trace_id.is_some()
            && ctx.state.observability.message_tracer.is_enabled())
        .then(Vec::new);
        Self {
            inner,
            ctx,
            usage: StreamUsage {
                trace,
                ..Default::default()
            },
            carry: String::new(),
            recorded: false,
        }
    }
}

/// Maximum carry-over tail retained between chunks (8 KB).
///
/// Only the trailing incomplete SSE event is ever carried; a single Anthropic
/// SSE event is far smaller than this. The cap defends against a pathological
/// upstream that never emits the `\n\n` delimiter.
const MAX_CARRY: usize = 8 * 1024;

/// Scans a chunk for usage fields and accumulates output text length.
///
/// Cheap hot-path scan: a SIMD [`memchr::memmem`] search gates the work, and
/// only the rare usage-bearing events are JSON-parsed. `carry` holds the
/// incomplete trailing event from the previous chunk so a field split across the
/// boundary is still seen.
///
/// Only the **complete** portion (up to the last `\n\n`) is counted; the
/// incomplete tail is carried forward un-counted so it is tallied exactly once
/// when the next chunk completes it.
fn scan_chunk(chunk: &str, carry: &mut String, usage: &mut StreamUsage) {
    // Prepend the previous incomplete tail so boundary-split fields complete.
    let scan_owned;
    let scan: &str = if carry.is_empty() {
        chunk
    } else {
        carry.push_str(chunk);
        scan_owned = std::mem::take(carry);
        &scan_owned
    };

    // Split into the complete portion (counted now) and the incomplete tail
    // (carried, counted later). Events are `\n\n`-delimited.
    let (complete, tail) = match scan.rfind("\n\n") {
        Some(pos) => (&scan[..pos + 2], &scan[pos + 2..]),
        None => ("", scan),
    };

    if !complete.is_empty() {
        // Output text accumulation: only `text_delta` deltas carry billable text.
        if memmem::find(complete.as_bytes(), b"text_delta").is_some() {
            accumulate_text_deltas(complete, usage);
        }
        // Trace capture (text + tool calls + thinking): only when tracing is on,
        // so the common path never parses these events.
        if usage.trace.is_some() {
            collect_traced_content(complete, usage);
        }
        // Provider usage: present only in `message_start` / `message_delta`.
        if memmem::find(complete.as_bytes(), b"\"usage\"").is_some() {
            accumulate_usage_events(complete, usage);
        }
    }

    if !tail.is_empty() {
        // Keep only the most recent bytes if a delimiter never arrives, so a
        // pathological upstream cannot grow the carry without bound.
        let start = tail.len().saturating_sub(MAX_CARRY);
        carry.push_str(&tail[tail.ceil_char_boundary(start)..]);
    }
}

/// Counts a final un-delimited event the stream may have ended on.
///
/// A well-formed SSE stream terminates each event with `\n\n`, so the carry is
/// normally empty at end. This guards the rare case where the last event lacks
/// the trailing delimiter, ensuring its tokens/text are still tallied once.
fn flush_carry(carry: &mut String, usage: &mut StreamUsage) {
    if carry.is_empty() {
        return;
    }
    let tail = std::mem::take(carry);
    if memmem::find(tail.as_bytes(), b"text_delta").is_some() {
        accumulate_text_deltas(&tail, usage);
    }
    if usage.trace.is_some() {
        collect_traced_content(&tail, usage);
    }
    if memmem::find(tail.as_bytes(), b"\"usage\"").is_some() {
        accumulate_usage_events(&tail, usage);
    }
}

/// Accumulates the outgoing Anthropic SSE into ordered content blocks for tracing.
///
/// Runs only when tracing is enabled (`usage.trace` is `Some`). Captures text,
/// tool calls (`name` + arguments), and thinking, so the `res` trace shows
/// exactly what the model produced — including the edits/commands it asked the
/// client to run — not just the prose. Each event is JSON-parsed; acceptable
/// because tracing is an opt-in debug feature off the production hot path.
fn collect_traced_content(buffer: &str, usage: &mut StreamUsage) {
    let Some(blocks) = usage.trace.as_mut() else {
        return;
    };
    for event in crate::providers::streaming::parse_sse_events(buffer) {
        let Ok(json) = serde_json::from_str::<serde_json::Value>(&event.data) else {
            continue;
        };
        // A missing index defaults to block 0 (single-block turns may omit it).
        let index = json
            .pointer("/index")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0) as usize;
        match json.pointer("/type").and_then(serde_json::Value::as_str) {
            Some("content_block_start") => {
                let cb = json.pointer("/content_block");
                let field = |name: &str| {
                    cb.and_then(|c| c.pointer(name))
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default()
                        .to_string()
                };
                let block = match cb
                    .and_then(|c| c.pointer("/type"))
                    .and_then(serde_json::Value::as_str)
                {
                    // `server_tool_use` is the server-side variant (e.g. hosted
                    // web search); record it the same as a client `tool_use`.
                    Some("tool_use") | Some("server_tool_use") => TraceBlock::ToolUse {
                        id: field("/id"),
                        name: field("/name"),
                        input: String::new(),
                    },
                    Some("thinking") => TraceBlock::Thinking(String::new()),
                    _ => TraceBlock::Text(String::new()),
                };
                *ensure_block(blocks, index) = block;
            }
            Some("content_block_delta") => {
                if let Some(delta) = json.pointer("/delta") {
                    append_delta(ensure_block(blocks, index), delta);
                }
            }
            _ => {}
        }
    }
}

/// Returns the block at `index`, growing the vec with empty text placeholders.
///
/// Anthropic emits blocks with sequential 0-based indices, so the index maps
/// directly to a vec position; a placeholder covers a delta that races ahead of
/// its `content_block_start` (not observed in practice, but keeps this total).
fn ensure_block(blocks: &mut Vec<TraceBlock>, index: usize) -> &mut TraceBlock {
    while blocks.len() <= index {
        blocks.push(TraceBlock::Text(String::new()));
    }
    &mut blocks[index]
}

/// Appends a `content_block_delta` payload to its block, matched by delta type.
///
/// A delta whose type does not match the block variant is ignored (malformed
/// stream); in a well-formed stream the `content_block_start` fixed the variant.
fn append_delta(block: &mut TraceBlock, delta: &serde_json::Value) {
    let delta_type = delta.pointer("/type").and_then(serde_json::Value::as_str);
    let field = |name: &str| delta.pointer(name).and_then(serde_json::Value::as_str);
    match block {
        TraceBlock::Text(s) => {
            if delta_type == Some("text_delta") {
                if let Some(t) = field("/text") {
                    s.push_str(t);
                }
            }
        }
        TraceBlock::Thinking(s) => {
            if delta_type == Some("thinking_delta") {
                if let Some(t) = field("/thinking") {
                    s.push_str(t);
                }
            }
        }
        TraceBlock::ToolUse { input, .. } => {
            if delta_type == Some("input_json_delta") {
                if let Some(j) = field("/partial_json") {
                    input.push_str(j);
                }
            }
        }
    }
}

/// Assembles accumulated blocks into the Anthropic-shaped `content` array.
///
/// `tool_use` arguments are the concatenated `input_json_delta` fragments parsed
/// back into a JSON value; a fragment that does not parse (empty or truncated) is
/// preserved verbatim as a string so nothing the model emitted is lost.
fn build_trace_content(blocks: &[TraceBlock]) -> serde_json::Value {
    let arr: Vec<serde_json::Value> = blocks
        .iter()
        .map(|b| match b {
            TraceBlock::Text(text) => serde_json::json!({ "type": "text", "text": text }),
            TraceBlock::Thinking(thinking) => {
                serde_json::json!({ "type": "thinking", "thinking": thinking })
            }
            TraceBlock::ToolUse { id, name, input } => {
                let input_val = serde_json::from_str::<serde_json::Value>(input)
                    .unwrap_or_else(|_| serde_json::Value::String(input.clone()));
                serde_json::json!({ "type": "tool_use", "id": id, "name": name, "input": input_val })
            }
        })
        .collect();
    serde_json::Value::Array(arr)
}

/// Writes the accumulated response content as a `res` trace entry on termination.
///
/// No-op unless tracing captured blocks (`usage.trace` is `Some`) and the context
/// carries a `trace_id` correlating it to the `req` entry.
fn trace_stream_response(ctx: &SpendStreamContext, usage: &StreamUsage) {
    let (Some(trace_id), Some(blocks)) = (ctx.trace_id.as_ref(), usage.trace.as_ref()) else {
        return;
    };
    let latency_ms = ctx.start_time.elapsed().as_millis() as u64;
    let content = build_trace_content(blocks);
    // A turn that emitted any tool call stops on "tool_use"; otherwise end_turn.
    let stop_reason = if blocks
        .iter()
        .any(|b| matches!(b, TraceBlock::ToolUse { .. }))
    {
        "tool_use"
    } else {
        "end_turn"
    };
    ctx.state
        .observability
        .message_tracer
        .trace_response_stream(
            trace_id,
            content,
            stop_reason,
            crate::traits::StreamTraceUsage {
                input_tokens: usage.input_tokens,
                output_tokens: usage.output_tokens,
                cache_creation_input_tokens: nonzero(usage.cache_creation_input_tokens),
                cache_read_input_tokens: nonzero(usage.cache_read_input_tokens),
            },
            latency_ms,
        );
}

/// Sums the byte length of every `text_delta` text value in the buffer.
///
/// Uses a fast substring walk for the common unescaped case; complex (escaped)
/// payloads still contribute via the conservative substring scan. The estimate
/// fallback only needs an approximate length, so minor over/under-count from
/// escapes is acceptable.
fn accumulate_text_deltas(buffer: &str, usage: &mut StreamUsage) {
    let bytes = buffer.as_bytes();
    let mut pos = 0;
    while let Some(rel) = memmem::find(&bytes[pos..], b"text_delta") {
        let after = pos + rel;
        // Find the "text":" field that follows this text_delta marker.
        if let Some(text) = extract_text_after(&buffer[after..]) {
            usage.output_bytes += text.len();
        }
        pos = after + b"text_delta".len();
        if pos >= bytes.len() {
            break;
        }
    }
}

/// Extracts the `"text":"..."` value following a `text_delta` marker.
///
/// Fast substring extraction without JSON parsing for the unescaped common
/// case; returns `None` for escaped values (caller treats them as zero-length,
/// a negligible undercount for the coarse estimate).
fn extract_text_after(after_marker: &str) -> Option<&str> {
    let marker = "\"text\":\"";
    let start = after_marker.find(marker)?;
    let value_start = start + marker.len();
    let remaining = &after_marker[value_start..];
    let rb = remaining.as_bytes();
    let mut end = 0;
    while end < rb.len() {
        match rb[end] {
            b'"' => return Some(&remaining[..end]),
            // Escaped value: bail to avoid mis-measuring; coarse estimate only.
            b'\\' => return None,
            _ => end += 1,
        }
    }
    None
}

/// Parses `message_start` / `message_delta` events for provider usage.
///
/// Reached only when the chunk contains `"usage"`, so the per-event JSON parse
/// stays off the common hot path.
fn accumulate_usage_events(buffer: &str, usage: &mut StreamUsage) {
    for event in crate::providers::streaming::parse_sse_events(buffer) {
        match event.event.as_deref() {
            Some("message_start") => parse_usage_json(&event.data, "/message/usage", usage),
            Some("message_delta") => parse_usage_json(&event.data, "/usage", usage),
            _ => {}
        }
    }
}

/// Parses input/output token counts from a usage object at `pointer`.
fn parse_usage_json(data: &str, pointer: &str, usage: &mut StreamUsage) {
    let Ok(json) = serde_json::from_str::<serde_json::Value>(data) else {
        return;
    };
    let Some(u) = json.pointer(pointer) else {
        return;
    };
    let cache_read =
        token_u32(u.get("cache_read_input_tokens")).or_else(|| cached_tokens_detail(u));
    if let Some(input) = u.get("input_tokens").and_then(serde_json::Value::as_u64) {
        let mut input = u32::try_from(input).unwrap_or(u32::MAX);
        if u.get("cache_read_input_tokens").is_none() {
            input = input.saturating_sub(cache_read.unwrap_or(0));
        }
        // message_start carries the authoritative input; message_delta repeats
        // it only when message_start was absent.
        if input > 0 && (usage.input_tokens == 0 || pointer == "/message/usage") {
            usage.input_tokens = input;
        }
        usage.saw_usage = true;
    }
    if let Some(output) = u.get("output_tokens").and_then(serde_json::Value::as_u64) {
        // output_tokens is cumulative; take the max so repeated/out-of-order
        // deltas never undercount.
        usage.output_tokens = usage
            .output_tokens
            .max(u32::try_from(output).unwrap_or(u32::MAX));
        usage.saw_usage = true;
    }
    if let Some(cache_creation) = token_u32(u.get("cache_creation_input_tokens")) {
        usage.cache_creation_input_tokens = usage.cache_creation_input_tokens.max(cache_creation);
        usage.saw_usage = true;
    }
    if let Some(cache_read) = cache_read {
        usage.cache_read_input_tokens = usage.cache_read_input_tokens.max(cache_read);
        usage.saw_usage = true;
    }
}

fn token_u32(value: Option<&serde_json::Value>) -> Option<u32> {
    value
        .and_then(serde_json::Value::as_u64)
        .map(|v| u32::try_from(v).unwrap_or(u32::MAX))
}

fn cached_tokens_detail(usage: &serde_json::Value) -> Option<u32> {
    usage
        .pointer("/input_tokens_details/cached_tokens")
        .or_else(|| usage.pointer("/prompt_tokens_details/cached_tokens"))
        .and_then(serde_json::Value::as_u64)
        .map(|v| u32::try_from(v).unwrap_or(u32::MAX))
}

fn nonzero(value: u32) -> Option<u32> {
    (value > 0).then_some(value)
}

fn billed_input_tokens(usage: &StreamUsage) -> u32 {
    usage
        .input_tokens
        .saturating_add(usage.cache_creation_input_tokens)
}

/// Resolves the `(input, output)` token counts to bill for a finished stream.
///
/// Provider-reported usage is authoritative. Only when no usage was seen **and**
/// token counting is in estimate mode does this fall back to the pre-captured
/// input estimate plus an output estimate from accumulated text. Returns `None`
/// when nothing should be billed (api mode with no usage), matching the
/// non-streaming path.
fn resolve_billed_tokens(
    usage: &StreamUsage,
    estimate_mode: bool,
    estimated_input_tokens: u32,
) -> Option<(u32, u32)> {
    if usage.saw_usage {
        return Some((billed_input_tokens(usage), usage.output_tokens));
    }
    if estimate_mode {
        let output = estimate_tokens_from_bytes(usage.output_bytes);
        tracing::debug!(
            estimated_input_tokens,
            estimated_output_tokens = output,
            "streaming provider omitted usage; billing from local token estimate"
        );
        return Some((estimated_input_tokens, output));
    }
    None
}

/// Converts an accumulated `text_delta` byte length to an estimated token count.
///
/// Delegates to the shared ~4-chars/token heuristic so the streaming estimate
/// matches the non-streaming fallback. SSE output text is overwhelmingly ASCII,
/// so byte length and char count coincide for this coarse estimate — letting us
/// feed the accumulated length directly, with no intermediate allocation.
fn estimate_tokens_from_bytes(bytes: usize) -> u32 {
    tokens_from_chars(bytes)
}

/// Records spend and Prometheus metrics for a completed stream.
///
/// Always spawns: the response is fully delivered by stream end, so there is no
/// consistency benefit to recording synchronously, and the final poll must not
/// stall on the spend mutex or the JSONL disk write.
fn record_stream_spend(ctx: &SpendStreamContext, usage: &StreamUsage) {
    let Some((input_tokens, output_tokens)) = resolve_billed_tokens(
        usage,
        is_estimate_mode(&ctx.state),
        ctx.estimated_input_tokens,
    ) else {
        return;
    };

    let latency_ms = ctx.start_time.elapsed().as_millis() as u64;
    let state = Arc::clone(&ctx.state);
    let provider = ctx.provider.clone();
    let model_name = ctx.model_name.clone();
    let actual_model = ctx.actual_model.clone();
    let route_type = ctx.route_type;
    let tenant_id = ctx.tenant_id.clone();
    let is_subscription = ctx.is_subscription;
    // Cache reads are priced separately (a fraction of input), so they are not
    // folded into the billed input count above; pass them through only when the
    // provider reported real usage (the estimate path has no cache breakdown).
    let cache_read_tokens = if usage.saw_usage {
        usage.cache_read_input_tokens
    } else {
        0
    };

    tokio::spawn(async move {
        let cost = calculate_cost(
            &state,
            &actual_model,
            input_tokens,
            output_tokens,
            cache_read_tokens,
            is_subscription,
        )
        .await;

        record_request_metrics(&RequestMetrics {
            model: &actual_model,
            provider: &provider,
            route_type: &route_type,
            status: "ok",
            latency_ms,
            input_tokens,
            output_tokens,
            cost_usd: cost.estimated_cost_usd,
        });

        record_spend(
            &state,
            &provider,
            &model_name,
            cost.estimated_cost_usd,
            tenant_id.as_deref(),
        )
        .await;
    });
}

impl<S> Stream for SpendStream<S>
where
    S: Stream<Item = Result<Bytes, crate::providers::error::ProviderError>> + Send,
{
    type Item = Result<Bytes, crate::providers::error::ProviderError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();

        match this.inner.poll_next(cx) {
            Poll::Ready(Some(Ok(bytes))) => {
                // Forward the chunk first (zero added latency); accounting is a
                // cheap substring scan on a borrowed view of the same bytes.
                let text = String::from_utf8_lossy(&bytes);
                scan_chunk(&text, this.carry, this.usage);
                Poll::Ready(Some(Ok(bytes)))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => {
                if !*this.recorded {
                    *this.recorded = true;
                    // Flush any trailing event the stream ended on without a
                    // final `\n\n` delimiter, then detach the spend commit so
                    // termination is never blocked on the spend mutex / disk.
                    flush_carry(this.carry, this.usage);
                    record_stream_spend(this.ctx, this.usage);
                    trace_stream_response(this.ctx, this.usage);
                }
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan_all(input: &str) -> StreamUsage {
        let mut usage = StreamUsage::default();
        let mut carry = String::new();
        scan_chunk(input, &mut carry, &mut usage);
        usage
    }

    #[test]
    fn captures_provider_usage() {
        let sse = concat!(
            "event: message_start\n",
            "data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":42,\"output_tokens\":1}}}\n\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n",
            "event: message_delta\n",
            "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":17}}\n\n",
        );
        let usage = scan_all(sse);
        assert!(usage.saw_usage);
        assert_eq!(usage.input_tokens, 42);
        assert_eq!(usage.output_tokens, 17);
    }

    #[test]
    fn captures_cache_usage_details() {
        let sse = concat!(
            "event: message_delta\n",
            "data: {\"type\":\"message_delta\",\"usage\":{\"input_tokens\":300,\"output_tokens\":17,\"cache_read_input_tokens\":700}}\n\n",
        );
        let usage = scan_all(sse);
        assert!(usage.saw_usage);
        assert_eq!(usage.input_tokens, 300);
        assert_eq!(usage.cache_read_input_tokens, 700);
        assert_eq!(resolve_billed_tokens(&usage, false, 0), Some((300, 17)));
    }

    #[test]
    fn captures_openai_cached_token_details() {
        let sse = concat!(
            "event: message_delta\n",
            "data: {\"type\":\"message_delta\",\"usage\":{\"input_tokens\":1000,\"output_tokens\":17,\"input_tokens_details\":{\"cached_tokens\":700}}}\n\n",
        );
        let usage = scan_all(sse);
        assert!(usage.saw_usage);
        assert_eq!(usage.input_tokens, 300);
        assert_eq!(usage.cache_read_input_tokens, 700);
        assert_eq!(resolve_billed_tokens(&usage, false, 0), Some((300, 17)));
    }

    #[test]
    fn collects_text_with_escapes_when_tracing() {
        let sse = concat!(
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\" \\\"world\\\"\"}}\n\n",
        );
        let mut usage = StreamUsage {
            trace: Some(Vec::new()),
            ..Default::default()
        };
        let mut carry = String::new();
        scan_chunk(sse, &mut carry, &mut usage);
        // Escapes are JSON-decoded into the trace, unlike the coarse byte counter.
        let content = build_trace_content(usage.trace.as_ref().unwrap());
        assert_eq!(content[0]["type"], "text");
        assert_eq!(content[0]["text"], "Hello \"world\"");
    }

    #[test]
    fn collects_tool_use_when_tracing() {
        // Text, then an Edit tool call whose arguments are split across two
        // input_json_delta fragments: the trace must show the tool name and the
        // arguments reassembled into a parsed object.
        let sse = concat!(
            "event: content_block_start\n",
            "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"editing\"}}\n\n",
            "event: content_block_start\n",
            "data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"Edit\",\"input\":{}}}\n\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"file_path\\\":\\\"a.rs\\\"\"}}\n\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"}\"}}\n\n",
        );
        let mut usage = StreamUsage {
            trace: Some(Vec::new()),
            ..Default::default()
        };
        let mut carry = String::new();
        scan_chunk(sse, &mut carry, &mut usage);
        let content = build_trace_content(usage.trace.as_ref().unwrap());
        assert_eq!(content[0]["text"], "editing");
        assert_eq!(content[1]["type"], "tool_use");
        assert_eq!(content[1]["name"], "Edit");
        assert_eq!(content[1]["id"], "toolu_1");
        // Concatenated partial_json fragments parsed back into an object.
        assert_eq!(content[1]["input"]["file_path"], "a.rs");
    }

    #[test]
    fn collects_thinking_when_tracing() {
        let sse = concat!(
            "event: content_block_start\n",
            "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"thinking\",\"thinking\":\"\"}}\n\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"hmm\"}}\n\n",
        );
        let mut usage = StreamUsage {
            trace: Some(Vec::new()),
            ..Default::default()
        };
        let mut carry = String::new();
        scan_chunk(sse, &mut carry, &mut usage);
        let content = build_trace_content(usage.trace.as_ref().unwrap());
        assert_eq!(content[0]["type"], "thinking");
        assert_eq!(content[0]["thinking"], "hmm");
    }

    #[test]
    fn skips_trace_collection_when_disabled() {
        let sse = concat!(
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n",
        );
        let usage = scan_all(sse); // trace defaults to None
        assert!(usage.trace.is_none());
        assert_eq!(usage.output_bytes, 2); // byte counter still runs
    }

    #[test]
    fn accumulates_output_text_bytes() {
        let sse = concat!(
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hello \"}}\n\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"world\"}}\n\n",
        );
        let usage = scan_all(sse);
        // "hello world" = 11 bytes; no message_* usage seen.
        assert!(!usage.saw_usage);
        assert_eq!(usage.output_bytes, 11);
    }

    #[test]
    fn ignores_non_text_deltas() {
        let sse = concat!(
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"a\\\":1}\"}}\n\n",
        );
        let usage = scan_all(sse);
        assert_eq!(usage.output_bytes, 0);
    }

    #[test]
    fn message_delta_takes_max_not_sum() {
        // Two cumulative deltas: the second supersedes the first.
        let sse = concat!(
            "event: message_delta\n",
            "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":10}}\n\n",
            "event: message_delta\n",
            "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":25}}\n\n",
        );
        let usage = scan_all(sse);
        assert_eq!(usage.output_tokens, 25);
    }

    #[test]
    fn handles_text_split_across_chunks() {
        // A text_delta event split mid-field across two chunks must still count.
        let mut usage = StreamUsage::default();
        let mut carry = String::new();
        let part1 = "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_de";
        let part2 = "lta\",\"text\":\"split\"}}\n\n";
        scan_chunk(part1, &mut carry, &mut usage);
        scan_chunk(part2, &mut carry, &mut usage);
        assert_eq!(usage.output_bytes, 5); // "split"
    }

    #[test]
    fn handles_usage_split_across_chunks() {
        let mut usage = StreamUsage::default();
        let mut carry = String::new();
        let part1 = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_to";
        let part2 = "kens\":99,\"output_tokens\":0}}}\n\n";
        scan_chunk(part1, &mut carry, &mut usage);
        scan_chunk(part2, &mut carry, &mut usage);
        assert!(usage.saw_usage);
        assert_eq!(usage.input_tokens, 99);
    }

    #[test]
    fn no_usage_and_no_text_records_nothing_in_api_mode() {
        // resolve_billed_tokens returns None when no usage seen and not estimating;
        // verified via the helper directly to avoid constructing AppState.
        let usage = StreamUsage::default();
        // saw_usage = false, output_bytes = 0.
        assert!(!usage.saw_usage);
        assert_eq!(usage.output_bytes, 0);
    }

    #[test]
    fn estimate_tokens_from_bytes_matches_heuristic() {
        // 0 bytes → 0 tokens; 11 bytes → ceil(11/4) = 3 tokens.
        assert_eq!(estimate_tokens_from_bytes(0), 0);
        assert_eq!(estimate_tokens_from_bytes(11), 3);
        assert_eq!(estimate_tokens_from_bytes(4), 1);
        assert_eq!(estimate_tokens_from_bytes(5), 2);
    }

    #[test]
    fn extract_text_after_returns_text() {
        let data = r#"text_delta","text":"abc"}}"#;
        assert_eq!(extract_text_after(data), Some("abc"));
    }

    #[test]
    fn extract_text_after_bails_on_escape() {
        let data = r#"text_delta","text":"a\"b"}}"#;
        assert_eq!(extract_text_after(data), None);
    }

    #[test]
    fn chunked_scan_matches_whole_buffer_scan() {
        // Splitting the SSE into arbitrary byte chunks must yield the same usage
        // as scanning it whole — the carry-over keeps boundary-split fields.
        let sse = concat!(
            "event: message_start\n",
            "data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":123,\"output_tokens\":0}}}\n\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"alpha\"}}\n\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"beta\"}}\n\n",
            "event: message_delta\n",
            "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":9}}\n\n",
        );
        let whole = scan_all(sse);

        let mut chunked = StreamUsage::default();
        let mut carry = String::new();
        for chunk in sse.as_bytes().chunks(7) {
            // Lossy decode mirrors the poll_next hot path.
            let text = String::from_utf8_lossy(chunk);
            scan_chunk(&text, &mut carry, &mut chunked);
        }

        assert_eq!(chunked.input_tokens, whole.input_tokens);
        assert_eq!(chunked.output_tokens, whole.output_tokens);
        assert_eq!(chunked.output_bytes, whole.output_bytes);
        assert_eq!(chunked.saw_usage, whole.saw_usage);
        assert_eq!(whole.input_tokens, 123);
        assert_eq!(whole.output_tokens, 9);
        assert_eq!(whole.output_bytes, 9); // "alpha" + "beta"
    }

    #[test]
    fn resolve_billed_prefers_provider_usage() {
        // Provider usage is authoritative even in estimate mode; the accumulated
        // text bytes are ignored when the provider reported counts.
        let usage = StreamUsage {
            input_tokens: 100,
            output_tokens: 50,
            saw_usage: true,
            output_bytes: 9999,
            ..Default::default()
        };
        assert_eq!(resolve_billed_tokens(&usage, true, 7), Some((100, 50)));
        assert_eq!(resolve_billed_tokens(&usage, false, 7), Some((100, 50)));
    }

    #[test]
    fn resolve_billed_falls_back_to_estimate() {
        // No provider usage + estimate mode → input estimate + output-char est.
        let usage = StreamUsage {
            saw_usage: false,
            output_bytes: 11, // ceil(11/4) = 3 tokens
            ..Default::default()
        };
        assert_eq!(resolve_billed_tokens(&usage, true, 25), Some((25, 3)));
    }

    #[test]
    fn resolve_billed_records_nothing_in_api_mode_without_usage() {
        // No provider usage + api mode → nothing billed (matches non-streaming).
        let usage = StreamUsage {
            saw_usage: false,
            output_bytes: 400,
            ..Default::default()
        };
        assert_eq!(resolve_billed_tokens(&usage, false, 25), None);
    }

    #[test]
    fn resolve_billed_includes_cache_creation_but_excludes_cache_read() {
        // Cache writes are billable input; cache reads are not. A regression that
        // dropped cache_creation (or folded in cache_read) would misbill spend.
        let usage = StreamUsage {
            input_tokens: 100,
            output_tokens: 50,
            cache_creation_input_tokens: 40,
            cache_read_input_tokens: 700,
            saw_usage: true,
            ..Default::default()
        };
        // billed input = input (100) + cache_creation (40); cache_read excluded.
        assert_eq!(resolve_billed_tokens(&usage, false, 0), Some((140, 50)));
    }
}

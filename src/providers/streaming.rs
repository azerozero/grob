use crate::features::token_pricing::get_pricing;
use bytes::Bytes;
use futures::stream::Stream;
use pin_project::pin_project;
use serde_json::Value;
use std::pin::Pin;
use std::task::{Context, Poll};

/// SSE event from provider
#[derive(Debug, Clone)]
pub struct SseEvent {
    pub event: Option<String>,
    pub data: String,
}

/// Parse SSE events from a byte stream
pub fn parse_sse_events(input: &str) -> Vec<SseEvent> {
    let mut events = Vec::with_capacity(4);
    let mut current_event: Option<String> = None;
    let mut current_data = String::new();

    for line in input.lines() {
        if line.is_empty() {
            // Empty line marks end of event
            if !current_data.is_empty() {
                events.push(SseEvent {
                    event: current_event.take(),
                    data: std::mem::take(&mut current_data),
                });
            }
        } else if let Some(data) = line.strip_prefix("data: ") {
            if !current_data.is_empty() {
                current_data.push('\n');
            }
            current_data.push_str(data);
        } else if let Some(event) = line.strip_prefix("event: ") {
            current_event = Some(event.to_string());
        }
        // Ignore other fields like "id:", "retry:", etc.
    }

    // Handle case where stream doesn't end with empty line
    if !current_data.is_empty() {
        events.push(SseEvent {
            event: current_event,
            data: current_data,
        });
    }

    events
}

/// Stream adapter that converts a reqwest Response stream into SSE events
#[pin_project]
pub struct SseStream<S> {
    #[pin]
    inner: S,
    buffer: String,
    /// Queue of parsed events waiting to be emitted
    event_queue: std::collections::VecDeque<SseEvent>,
}

impl<S> SseStream<S> {
    pub fn new(stream: S) -> Self {
        Self {
            inner: stream,
            buffer: String::new(),
            event_queue: std::collections::VecDeque::new(),
        }
    }
}

impl<S> Stream for SseStream<S>
where
    S: Stream<Item = Result<Bytes, reqwest::Error>>,
{
    type Item = Result<SseEvent, reqwest::Error>;

    /// Buffer incoming bytes and split on `"\n\n"` (SSE event delimiter).
    ///
    /// Bytes from the inner stream accumulate in `self.buffer`. When at least one
    /// complete `"\n\n"` delimiter is found, everything up to the last delimiter
    /// is parsed into `SseEvent`s and queued. The incomplete trailing portion
    /// stays in the buffer for the next poll. This ensures partial chunks
    /// (common with HTTP chunked transfer) are reassembled correctly.
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();

        // First, check if we have queued events to emit
        if let Some(event) = this.event_queue.pop_front() {
            return Poll::Ready(Some(Ok(event)));
        }

        // Poll the inner stream for new data
        match this.inner.poll_next(cx) {
            Poll::Ready(Some(Ok(bytes))) => {
                // Add new bytes to buffer
                if let Ok(text) = std::str::from_utf8(&bytes) {
                    this.buffer.push_str(text);

                    // Try to parse complete events from buffer
                    // Note: We only clear buffer up to the last complete event
                    if let Some(last_event_end) = this.buffer.rfind("\n\n") {
                        let complete_portion = &this.buffer[..last_event_end + 2];
                        let events = parse_sse_events(complete_portion);

                        // Add all parsed events to queue
                        for event in events {
                            this.event_queue.push_back(event);
                        }

                        // Keep only the incomplete portion in buffer (in-place, no allocation)
                        this.buffer.drain(..last_event_end + 2);

                        // Return the first queued event if available
                        if let Some(event) = this.event_queue.pop_front() {
                            return Poll::Ready(Some(Ok(event)));
                        }
                    }
                }

                // If no complete event yet, continue polling
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => {
                // Stream ended - check if buffer has remaining data
                if !this.buffer.is_empty() {
                    let events = parse_sse_events(this.buffer);
                    *this.buffer = String::new();

                    // Add all parsed events to queue
                    for event in events {
                        this.event_queue.push_back(event);
                    }
                }

                // Return next queued event, or None if queue is empty
                if let Some(event) = this.event_queue.pop_front() {
                    return Poll::Ready(Some(Ok(event)));
                }

                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Token counts tracked during stream processing.
struct StreamTokens {
    input: u64,
    output: u64,
    cache_creation: u64,
    cache_read: u64,
}

/// Stream adapter that logs useful information from SSE events while passing through original bytes
#[pin_project]
pub struct LoggingSseStream<S> {
    #[pin]
    inner: S,
    provider_name: String,
    model_name: String,
    buffer: Vec<u8>,
    logged_message_start: bool,
    start_time: std::time::Instant,
    first_token_time: Option<std::time::Instant>,
    output_tokens: u64,
    input_tokens: u64,
    cache_creation: u64,
    cache_read: u64,
}

impl<S> LoggingSseStream<S> {
    pub fn new(stream: S, provider_name: String, model_name: String) -> Self {
        Self {
            inner: stream,
            provider_name,
            model_name,
            buffer: Vec::new(),
            logged_message_start: false,
            start_time: std::time::Instant::now(),
            first_token_time: None,
            output_tokens: 0,
            input_tokens: 0,
            cache_creation: 0,
            cache_read: 0,
        }
    }
}

impl<S> LoggingSseStream<S> {
    /// Process SSE events from a chunk to track usage metrics.
    fn track_events(
        buffer: &[u8],
        logged_message_start: &mut bool,
        first_token_time: &mut Option<std::time::Instant>,
        input_tokens: &mut u64,
        cache_creation: &mut u64,
        cache_read: &mut u64,
        output_tokens: &mut u64,
    ) {
        let Ok(text) = std::str::from_utf8(buffer) else {
            return;
        };
        if !text.contains("\n\n") {
            return;
        }
        for event in parse_sse_events(text) {
            match event.event.as_deref() {
                Some("message_start") if !*logged_message_start => {
                    if let Ok(json) = serde_json::from_str::<Value>(&event.data) {
                        if let Some(usage) = json.pointer("/message/usage") {
                            *input_tokens = usage
                                .get("input_tokens")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0);
                            *cache_creation = usage
                                .get("cache_creation_input_tokens")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0);
                            *cache_read = usage
                                .get("cache_read_input_tokens")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0);
                        }
                    }
                    *logged_message_start = true;
                }
                Some("content_block_delta") => {
                    if first_token_time.is_none() {
                        *first_token_time = Some(std::time::Instant::now());
                    }
                }
                Some("message_delta") => {
                    if let Ok(json) = serde_json::from_str::<Value>(&event.data) {
                        if let Some(usage) = json.get("usage") {
                            *output_tokens += usage
                                .get("output_tokens")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0);
                            if let Some(input) = usage.get("input_tokens").and_then(|v| v.as_u64())
                            {
                                if input > 0 && *input_tokens == 0 {
                                    *input_tokens = input;
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    /// Log final stream stats and record Prometheus metrics.
    fn log_final_stats(
        provider_name: &str,
        model_name: &str,
        start_time: std::time::Instant,
        first_token_time: Option<std::time::Instant>,
        tokens: &StreamTokens,
    ) {
        let total_time = start_time.elapsed();
        let ttft = first_token_time
            .map(|t| t.duration_since(start_time))
            .unwrap_or(total_time);

        let tok_per_sec = if total_time.as_secs_f64() > 0.0 && tokens.output > 0 {
            tokens.output as f64 / total_time.as_secs_f64()
        } else {
            0.0
        };

        let total_input = tokens.input + tokens.cache_creation + tokens.cache_read;

        let cache_info = if tokens.cache_creation > 0 || tokens.cache_read > 0 {
            let cache_pct = if total_input > 0 {
                (tokens.cache_read * 100) / total_input
            } else {
                0
            };
            format!(" cache:{}%", cache_pct)
        } else {
            String::new()
        };

        // Keep last 2 slash-separated segments for cleaner logs
        let model_display: std::borrow::Cow<str> = {
            let slash_count = model_name.matches('/').count();
            if slash_count >= 2 {
                let parts: Vec<&str> = model_name.rsplitn(3, '/').collect();
                format!("{}/{}", parts[1], parts[0]).into()
            } else {
                model_name.into()
            }
        };

        let cost = get_pricing(model_name)
            .map(|p| p.calculate(total_input as u32, tokens.output as u32))
            .unwrap_or(0.0);
        let cost_info = if cost > 0.0 {
            format!(" ${:.4}", cost)
        } else {
            String::new()
        };

        tracing::info!(
            "📊 {}:{} {}ms ttft:{}ms {:.1}t/s out:{} in:{}{}{}",
            provider_name,
            model_display,
            total_time.as_millis(),
            ttft.as_millis(),
            tok_per_sec,
            tokens.output,
            total_input,
            cache_info,
            cost_info
        );

        let model_label = model_name.to_string();
        let provider_label = provider_name.to_string();
        metrics::counter!("grob_requests_total",
            "model" => model_label.clone(), "provider" => provider_label.clone(), "route_type" => "stream", "status" => "ok"
        ).increment(1);
        metrics::histogram!("grob_request_duration_seconds",
            "model" => model_label.clone(), "provider" => provider_label.clone()
        )
        .record(total_time.as_secs_f64());
        metrics::counter!("grob_tokens_input_total",
            "model" => model_label.clone(), "provider" => provider_label.clone()
        )
        .increment(total_input);
        metrics::counter!("grob_tokens_output_total",
            "model" => model_label.clone(), "provider" => provider_label.clone()
        )
        .increment(tokens.output);
        if cost > 0.0 {
            metrics::gauge!("grob_estimated_cost_usd",
                "model" => model_label, "provider" => provider_label
            )
            .increment(cost);
        }
    }
}

impl<S, E> Stream for LoggingSseStream<S>
where
    S: Stream<Item = Result<Bytes, E>>,
{
    type Item = Result<Bytes, E>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.as_mut().project().inner.poll_next(cx) {
            Poll::Ready(Some(Ok(bytes))) => {
                let this = self.as_mut().project();
                this.buffer.extend_from_slice(&bytes);

                Self::track_events(
                    this.buffer,
                    this.logged_message_start,
                    this.first_token_time,
                    this.input_tokens,
                    this.cache_creation,
                    this.cache_read,
                    this.output_tokens,
                );

                // Keep buffer from growing unbounded
                if this.buffer.len() > 1024 * 10 {
                    this.buffer.clear();
                }

                Poll::Ready(Some(Ok(bytes)))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => {
                let this = self.as_ref().project_ref();
                Self::log_final_stats(
                    this.provider_name,
                    this.model_name,
                    *this.start_time,
                    *this.first_token_time,
                    &StreamTokens {
                        input: *this.input_tokens,
                        output: *this.output_tokens,
                        cache_creation: *this.cache_creation,
                        cache_read: *this.cache_read,
                    },
                );
                self.as_mut().project().buffer.clear();
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sse_single_event() {
        let input = "event: message\ndata: {\"test\":\"value\"}\n\n";
        let events = parse_sse_events(input);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event.as_deref(), Some("message"));
        assert_eq!(events[0].data, "{\"test\":\"value\"}");
    }

    #[test]
    fn test_parse_sse_multiple_events() {
        let input = "event: start\ndata: {\"a\":1}\n\nevent: delta\ndata: {\"b\":2}\n\n";
        let events = parse_sse_events(input);

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event.as_deref(), Some("start"));
        assert_eq!(events[1].event.as_deref(), Some("delta"));
    }

    #[test]
    fn test_parse_sse_no_event_type() {
        let input = "data: plain data\n\n";
        let events = parse_sse_events(input);

        assert_eq!(events.len(), 1);
        assert!(events[0].event.is_none());
        assert_eq!(events[0].data, "plain data");
    }
}

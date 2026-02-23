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
    let mut events = Vec::new();
    let mut current_event: Option<String> = None;
    let mut current_data = String::new();

    for line in input.lines() {
        if line.is_empty() {
            // Empty line marks end of event
            if !current_data.is_empty() {
                events.push(SseEvent {
                    event: current_event.take(),
                    data: current_data.clone(),
                });
                current_data.clear();
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

                        // Keep only the incomplete portion in buffer
                        *this.buffer = this.buffer[last_event_end + 2..].to_string();

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

impl<S, E> Stream for LoggingSseStream<S>
where
    S: Stream<Item = Result<Bytes, E>>,
{
    type Item = Result<Bytes, E>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.as_mut().project().inner.poll_next(cx) {
            Poll::Ready(Some(Ok(bytes))) => {
                // Accumulate bytes for parsing and track events
                let this = self.as_mut().project();
                this.buffer.extend_from_slice(&bytes);

                // Clone data we need for event processing
                let buffer_clone = this.buffer.clone();

                // Parse events from accumulated buffer
                if let Ok(text) = std::str::from_utf8(&buffer_clone) {
                    if text.contains("\n\n") {
                        let events = parse_sse_events(text);

                        for event in events {
                            match event.event.as_deref() {
                                Some("message_start") if !*this.logged_message_start => {
                                    // Extract cache stats
                                    if let Ok(json) = serde_json::from_str::<Value>(&event.data) {
                                        if let Some(message) = json.get("message") {
                                            if let Some(usage) = message.get("usage") {
                                                *this.input_tokens = usage
                                                    .get("input_tokens")
                                                    .and_then(|v| v.as_u64())
                                                    .unwrap_or(0);
                                                *this.cache_creation = usage
                                                    .get("cache_creation_input_tokens")
                                                    .and_then(|v| v.as_u64())
                                                    .unwrap_or(0);
                                                *this.cache_read = usage
                                                    .get("cache_read_input_tokens")
                                                    .and_then(|v| v.as_u64())
                                                    .unwrap_or(0);
                                            }
                                        }
                                    }
                                    *this.logged_message_start = true;
                                }
                                Some("content_block_delta") => {
                                    // Mark first token arrival
                                    if this.first_token_time.is_none() {
                                        *this.first_token_time = Some(std::time::Instant::now());
                                    }
                                }
                                Some("message_delta") => {
                                    // Track tokens (output_tokens always, input_tokens for OpenAI providers)
                                    if let Ok(json) = serde_json::from_str::<Value>(&event.data) {
                                        if let Some(usage) = json.get("usage") {
                                            *this.output_tokens += usage
                                                .get("output_tokens")
                                                .and_then(|v| v.as_u64())
                                                .unwrap_or(0);
                                            // OpenAI providers include input_tokens in message_delta instead of message_start
                                            if let Some(input) =
                                                usage.get("input_tokens").and_then(|v| v.as_u64())
                                            {
                                                if input > 0 && *this.input_tokens == 0 {
                                                    *this.input_tokens = input;
                                                }
                                            }
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }

                // Keep buffer from growing unbounded
                let this = self.as_mut().project();
                if this.buffer.len() > 1024 * 10 {
                    this.buffer.clear();
                }

                // Pass through original bytes unchanged
                Poll::Ready(Some(Ok(bytes)))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => {
                // Stream ended - log final stats
                let this = self.as_ref().project_ref();
                let total_time = this.start_time.elapsed();
                let ttft = this
                    .first_token_time
                    .map(|t| t.duration_since(*this.start_time))
                    .unwrap_or(total_time);

                let tok_per_sec = if total_time.as_secs_f64() > 0.0 && *this.output_tokens > 0 {
                    *this.output_tokens as f64 / total_time.as_secs_f64()
                } else {
                    0.0
                };

                let total_input = *this.input_tokens + *this.cache_creation + *this.cache_read;

                // Build cache info string if caching was used
                let cache_info = if *this.cache_creation > 0 || *this.cache_read > 0 {
                    let cache_pct = if total_input > 0 {
                        (*this.cache_read * 100) / total_input
                    } else {
                        0
                    };
                    format!(" cache:{}%", cache_pct)
                } else {
                    String::new()
                };
                // Keep last 2 slash-separated segments for cleaner logs (e.g. "accounts/fireworks/models/x" -> "models/x")
                let model_display: std::borrow::Cow<str> = {
                    let slash_count = this.model_name.matches('/').count();
                    if slash_count >= 2 {
                        let parts: Vec<&str> = this.model_name.rsplitn(3, '/').collect();
                        format!("{}/{}", parts[1], parts[0]).into()
                    } else {
                        this.model_name.as_str().into()
                    }
                };
                let cost = get_pricing(this.model_name)
                    .map(|p| p.calculate(total_input as u32, *this.output_tokens as u32))
                    .unwrap_or(0.0);
                let cost_info = if cost > 0.0 {
                    format!(" ${:.4}", cost)
                } else {
                    String::new()
                };
                tracing::info!(
                    "📊 {}:{} {}ms ttft:{}ms {:.1}t/s out:{} in:{}{}{}",
                    this.provider_name,
                    model_display,
                    total_time.as_millis(),
                    ttft.as_millis(),
                    tok_per_sec,
                    *this.output_tokens,
                    total_input,
                    cache_info,
                    cost_info
                );

                // Record Prometheus metrics
                let labels = [
                    ("model", this.model_name.to_string()),
                    ("provider", this.provider_name.to_string()),
                    ("route_type", "stream".to_string()),
                    ("status", "ok".to_string()),
                ];
                metrics::counter!("grob_requests_total", &labels).increment(1);
                metrics::histogram!("grob_request_duration_seconds",
                    "model" => this.model_name.to_string(), "provider" => this.provider_name.to_string()
                ).record(total_time.as_secs_f64());
                metrics::counter!("grob_tokens_input_total",
                    "model" => this.model_name.to_string(), "provider" => this.provider_name.to_string()
                ).increment(total_input);
                metrics::counter!("grob_tokens_output_total",
                    "model" => this.model_name.to_string(), "provider" => this.provider_name.to_string()
                ).increment(*this.output_tokens);
                if cost > 0.0 {
                    metrics::gauge!("grob_estimated_cost_usd",
                        "model" => this.model_name.to_string(), "provider" => this.provider_name.to_string()
                    ).increment(cost);
                }

                // Clear buffer
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

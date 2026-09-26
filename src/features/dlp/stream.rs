//! Output DLP retains complete text blocks so matching is independent of token boundaries.

use super::DlpEngine;
use crate::providers::{
    error::ProviderError,
    guarded_stream::{protocol_error, Event, FrameStream, BUFFER_LIMIT, EVENT_COUNT_LIMIT},
};
use bytes::Bytes;
use futures::Stream;
use pin_project::pin_project;
use std::{
    borrow::Cow,
    collections::{BTreeMap, HashSet, VecDeque},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

const MAX_CANARIES_PER_STREAM: usize = 20;

/// Checks each complete text block before releasing any of its text.
///
/// SSE framing and retained events each have a 1 MiB limit. A block that is
/// incomplete, malformed or exceeds the limit terminates the stream. Arbitrary
/// regexes cannot safely use a fixed look-behind window, so text is delivered
/// at block completion rather than token by token when output DLP is enabled.
#[pin_project]
pub struct DlpStream<S> {
    #[pin]
    inner: FrameStream<S>,
    engine: Arc<DlpEngine>,
    pending: Vec<Event>,
    texts: BTreeMap<u64, String>,
    open: HashSet<u64>,
    retained_bytes: usize,
    ready: VecDeque<Bytes>,
    canary_count: usize,
    done: bool,
}

impl<S> DlpStream<S> {
    /// Wraps the provider's canonical SSE stream with preventive output scanning.
    pub fn new(inner: S, engine: Arc<DlpEngine>) -> Self {
        Self {
            inner: FrameStream::new(inner),
            engine,
            pending: Vec::new(),
            texts: BTreeMap::new(),
            open: HashSet::new(),
            retained_bytes: 0,
            ready: VecDeque::new(),
            canary_count: 0,
            done: false,
        }
    }
}

fn check_text(engine: &DlpEngine, text: &str) -> Result<(), ProviderError> {
    engine
        .check_response_url_exfil(text)
        .map_err(|_| protocol_error("DLP blocked response URL"))?;
    engine
        .check_response_injection(text)
        .map_err(|_| protocol_error("DLP blocked response injection"))?;
    Ok(())
}

fn release_blocks(
    engine: &Arc<DlpEngine>,
    pending: &mut Vec<Event>,
    texts: &mut BTreeMap<u64, String>,
    canary_count: &mut usize,
) -> Result<VecDeque<Bytes>, ProviderError> {
    for text in texts.values_mut() {
        check_text(engine, text)?;
        engine.scan_entropy(text);
        *text = sanitize_with_circuit_breaker(text, engine, canary_count).into_owned();
        check_text(engine, text)?;
        if text.len() > BUFFER_LIMIT {
            return Err(protocol_error("DLP transformed text exceeds 1 MiB"));
        }
    }
    let mut ready = VecDeque::new();
    let mut size = 0usize;
    let mut push = |bytes: Bytes| -> Result<(), ProviderError> {
        size = size.saturating_add(bytes.len());
        if size > BUFFER_LIMIT {
            return Err(protocol_error("DLP transformed events exceed 1 MiB"));
        }
        ready.push_back(bytes);
        Ok(())
    };
    for mut event in pending.drain(..) {
        match event.kind() {
            "content_block_start" if event.value["content_block"]["type"] == "text" => {
                event.value["content_block"]["text"] = "".into();
                push(Event::from_value(event.value).bytes)?;
            }
            "content_block_delta" if event.value["delta"]["type"] == "text_delta" => {}
            "content_block_stop" => {
                if let Some(text) = texts.remove(&event.index()?) {
                    if !text.is_empty() {
                        push(Event::from_value(serde_json::json!({"type":"content_block_delta", "index":event.index()?, "delta":{"type":"text_delta", "text":text}})).bytes)?;
                    }
                }
                push(event.bytes)?;
            }
            _ => push(event.bytes)?,
        }
    }
    Ok(ready)
}

impl<S: Stream<Item = Result<Bytes, ProviderError>>> Stream for DlpStream<S> {
    type Item = Result<Bytes, ProviderError>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();
        if *this.done {
            return Poll::Ready(None);
        }
        if let Some(bytes) = this.ready.pop_front() {
            return Poll::Ready(Some(Ok(bytes)));
        }
        let event = match this.inner.poll_next(cx) {
            Poll::Ready(Some(Ok(event))) => event,
            Poll::Ready(Some(Err(error))) => {
                *this.done = true;
                return Poll::Ready(Some(Err(error)));
            }
            Poll::Ready(None) => {
                *this.done = true;
                return if this.open.is_empty() {
                    Poll::Ready(None)
                } else {
                    Poll::Ready(Some(Err(protocol_error("Incomplete DLP text block"))))
                };
            }
            Poll::Pending => return Poll::Pending,
        };
        let result = (|| {
            match event.kind() {
                "content_block_start" if event.value["content_block"]["type"] == "text" => {
                    let index = event.index()?;
                    if this.texts.contains_key(&index) {
                        return Err(protocol_error("Duplicate DLP text block"));
                    }
                    let text = event.value["content_block"]["text"]
                        .as_str()
                        .ok_or_else(|| protocol_error("Missing initial text"))?;
                    this.texts.insert(index, text.to_owned());
                    this.open.insert(index);
                }
                "content_block_delta" if event.value["delta"]["type"] == "text_delta" => {
                    let index = event.index()?;
                    if !this.open.contains(&index) {
                        return Err(protocol_error("Text delta without an open block"));
                    }
                    let text = event.value["delta"]["text"]
                        .as_str()
                        .ok_or_else(|| protocol_error("Invalid text delta"))?;
                    this.texts
                        .get_mut(&index)
                        .expect("open text block")
                        .push_str(text);
                }
                "content_block_stop" => {
                    this.open.remove(&event.index()?);
                }
                "message_stop" | "message_delta" if !this.open.is_empty() => {
                    return Err(protocol_error("Message ended before DLP text block"))
                }
                _ => {}
            }
            Ok(())
        })();
        if let Err(error) = result {
            *this.done = true;
            return Poll::Ready(Some(Err(error)));
        }
        if this.texts.is_empty() {
            return Poll::Ready(Some(Ok(event.bytes)));
        }
        *this.retained_bytes = this.retained_bytes.saturating_add(event.bytes.len());
        if *this.retained_bytes > BUFFER_LIMIT || this.pending.len() >= EVENT_COUNT_LIMIT {
            *this.done = true;
            return Poll::Ready(Some(Err(protocol_error(
                "DLP text group exceeds buffer limit",
            ))));
        }
        this.pending.push(event);
        if this.open.is_empty() {
            match release_blocks(this.engine, this.pending, this.texts, this.canary_count) {
                Ok(ready) => {
                    *this.ready = ready;
                    *this.retained_bytes = 0;
                }
                Err(error) => {
                    *this.done = true;
                    metrics::counter!("grob_dlp_stream_blocked_total").increment(1);
                    return Poll::Ready(Some(Err(error)));
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
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
        return Cow::Owned(
            engine
                .sanitize_response_text(&redact_only(text, engine))
                .into_owned(),
        );
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

#[cfg(test)]
#[path = "stream_tests.rs"]
mod tests;

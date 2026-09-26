//! Bounded SSE framing for security decisions. Never inspect transport chunks as events.

use super::error::ProviderError;
use bytes::{Buf, Bytes};
use futures::Stream;
use pin_project::pin_project;
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    pin::Pin,
    task::{Context, Poll},
};

pub(crate) const BUFFER_LIMIT: usize = 1024 * 1024;
pub(crate) const EVENT_COUNT_LIMIT: usize = 4096;

pub(crate) fn protocol_error(message: &str) -> ProviderError {
    ProviderError::ProtocolError(message.to_owned())
}

pub(crate) struct Event {
    pub bytes: Bytes,
    pub value: Value,
}

impl Event {
    pub fn kind(&self) -> &str {
        self.value["type"].as_str().unwrap_or("")
    }
    pub fn index(&self) -> Result<u64, ProviderError> {
        self.value["index"]
            .as_u64()
            .ok_or_else(|| protocol_error("SSE content block has no valid index"))
    }
    pub fn from_value(value: Value) -> Self {
        let kind = value["type"].as_str().unwrap_or("message");
        let bytes = Bytes::from(format!("event: {kind}\ndata: {value}\n\n"));
        Self { bytes, value }
    }
}

#[derive(Default)]
struct Decoder {
    line: Vec<u8>,
    event: Vec<u8>,
    after_cr: bool,
    started: bool,
}

impl Decoder {
    fn push(&mut self, byte: u8) -> Result<Option<Event>, ProviderError> {
        if self.after_cr && byte == b'\n' {
            self.after_cr = false;
            return Ok(None);
        }
        self.after_cr = byte == b'\r';
        if byte == b'\r' || byte == b'\n' {
            if !self.started {
                if self.line.starts_with(b"\xef\xbb\xbf") {
                    self.line.drain(..3);
                }
                self.started = true;
            }
            if self.line.is_empty() {
                if self.event.is_empty() {
                    return Ok(None);
                }
                let result = self.parse();
                self.event.clear();
                return result.map(Some);
            }
            self.event.append(&mut self.line);
            self.event.push(b'\n');
        } else {
            self.line.push(byte);
        }
        if self.line.len() + self.event.len() > BUFFER_LIMIT {
            return Err(protocol_error("SSE event exceeds 1 MiB"));
        }
        Ok(None)
    }

    fn parse(&self) -> Result<Event, ProviderError> {
        let text =
            std::str::from_utf8(&self.event).map_err(|_| protocol_error("Invalid SSE UTF-8"))?;
        let mut data = Vec::new();
        let mut event_name = None;
        for line in text.lines() {
            let (field, value) = line.split_once(':').unwrap_or((line, ""));
            let value = value.strip_prefix(' ').unwrap_or(value);
            match field {
                "data" => data.push(value),
                "event" => event_name = Some(value),
                _ => {}
            }
        }
        let data = data.join("\n");
        if data.is_empty() || data == "[DONE]" {
            return Ok(Event {
                bytes: Bytes::from(format!("{text}\n")),
                value: Value::Null,
            });
        }
        let value: Value =
            serde_json::from_str(&data).map_err(|_| protocol_error("Invalid SSE JSON"))?;
        if value["type"]
            .as_str()
            .is_some_and(|kind| kind.contains(['\r', '\n']))
        {
            return Err(protocol_error("Invalid SSE event type"));
        }
        if let (Some(name), Some(kind)) = (event_name, value["type"].as_str()) {
            if name != kind {
                return Err(protocol_error("Conflicting SSE event type"));
            }
        }
        // Parse JSON structurally and emit one complete, canonical event. Unicode
        // escapes, field order, optional spaces and multiline data are equivalent.
        Ok(Event::from_value(value))
    }
}

#[pin_project]
pub(crate) struct FrameStream<S> {
    #[pin]
    inner: S,
    input: Bytes,
    decoder: Decoder,
    done: bool,
}

impl<S> FrameStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            input: Bytes::new(),
            decoder: Decoder::default(),
            done: false,
        }
    }
}

impl<S: Stream<Item = Result<Bytes, ProviderError>>> Stream for FrameStream<S> {
    type Item = Result<Event, ProviderError>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        if *this.done {
            return Poll::Ready(None);
        }
        for _ in 0..32 {
            while this.input.has_remaining() {
                let byte = this.input.get_u8();
                match this.decoder.push(byte) {
                    Ok(Some(event)) => return Poll::Ready(Some(Ok(event))),
                    Ok(None) => {}
                    Err(error) => {
                        *this.done = true;
                        return Poll::Ready(Some(Err(error)));
                    }
                }
            }
            match this.inner.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(bytes))) => {
                    if bytes.len() > BUFFER_LIMIT {
                        *this.done = true;
                        return Poll::Ready(Some(Err(protocol_error(
                            "SSE transport chunk exceeds 1 MiB",
                        ))));
                    }
                    *this.input = bytes;
                }
                Poll::Ready(Some(Err(error))) => {
                    *this.done = true;
                    return Poll::Ready(Some(Err(error)));
                }
                Poll::Ready(None) => {
                    *this.done = true;
                    return if this.decoder.line.is_empty() && this.decoder.event.is_empty() {
                        Poll::Ready(None)
                    } else {
                        Poll::Ready(Some(Err(protocol_error("Incomplete SSE event"))))
                    };
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

/// Serializes interleaved tool blocks in start order before single-tool authorization.
/// Block indices and payloads stay intact; no block is released before its stop.
#[pin_project]
pub(crate) struct ToolBlockStream<S> {
    #[pin]
    inner: FrameStream<S>,
    groups: Vec<Vec<Event>>,
    indices: HashMap<u64, usize>,
    open: HashSet<u64>,
    ready: VecDeque<Event>,
    bytes: usize,
    count: usize,
    done: bool,
}

impl<S> ToolBlockStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner: FrameStream::new(inner),
            groups: Vec::new(),
            indices: HashMap::new(),
            open: HashSet::new(),
            ready: VecDeque::new(),
            bytes: 0,
            count: 0,
            done: false,
        }
    }
}

impl<S: Stream<Item = Result<Bytes, ProviderError>>> Stream for ToolBlockStream<S> {
    type Item = Result<Bytes, ProviderError>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();
        if *this.done {
            return Poll::Ready(None);
        }
        if let Some(event) = this.ready.pop_front() {
            return Poll::Ready(Some(Ok(event.bytes)));
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
                    Poll::Ready(Some(Err(protocol_error("Incomplete tool block"))))
                };
            }
            Poll::Pending => return Poll::Pending,
        };
        let starts_tool = event.kind() == "content_block_start"
            && event.value["content_block"]["type"] == "tool_use";
        if starts_tool
            && (event.value["content_block"]["name"]
                .as_str()
                .is_none_or(str::is_empty)
                || event.value["index"]
                    .as_u64()
                    .is_none_or(|index| index > u64::from(u32::MAX)))
        {
            *this.done = true;
            return Poll::Ready(Some(Err(protocol_error("Invalid tool name or index"))));
        }
        if this.open.is_empty() && !starts_tool {
            if event.value["delta"]["type"] == "input_json_delta" {
                *this.done = true;
                return Poll::Ready(Some(Err(protocol_error("Tool input without a tool block"))));
            }
            return Poll::Ready(Some(Ok(event.bytes)));
        }
        *this.bytes += event.bytes.len();
        *this.count += 1;
        let result = (|| {
            if *this.bytes > BUFFER_LIMIT || *this.count > EVENT_COUNT_LIMIT {
                return Err(protocol_error("Tool group exceeds buffer limit"));
            }
            let slot = match event.kind() {
                "content_block_start" => {
                    let index = event.index()?;
                    if this.indices.contains_key(&index) {
                        return Err(protocol_error("Duplicate content block"));
                    }
                    let slot = this.groups.len();
                    this.groups.push(Vec::new());
                    this.indices.insert(index, slot);
                    this.open.insert(index);
                    slot
                }
                "content_block_delta" | "content_block_stop" => {
                    let index = event.index()?;
                    if !this.open.contains(&index) {
                        return Err(protocol_error("Unknown content block"));
                    }
                    if event.kind() == "content_block_stop" {
                        this.open.remove(&index);
                    }
                    this.indices[&index]
                }
                "message_stop" | "message_delta" => {
                    return Err(protocol_error("Message ended before tool block"))
                }
                _ => {
                    this.groups.push(Vec::new());
                    this.groups.len() - 1
                }
            };
            this.groups[slot].push(event);
            Ok(())
        })();
        if let Err(error) = result {
            *this.done = true;
            return Poll::Ready(Some(Err(error)));
        }
        if this.open.is_empty() {
            this.ready.extend(this.groups.drain(..).flatten());
            this.indices.clear();
            *this.bytes = 0;
            *this.count = 0;
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

//! Central trait contracts for the dispatch pipeline.
//!
//! Defines the two abstractions that are genuinely polymorphic: tracing (two
//! implementations) and provider availability (scorer or circuit-breaker registry).
//! Concrete types implement them in their own modules. Anything with a single
//! implementation is called directly on the concrete type instead.

use crate::models::{CanonicalRequest, RouteType};
use crate::providers::ProviderResponse;
use crate::security::circuit_breaker::CircuitState;
use async_trait::async_trait;
use std::collections::HashMap;

// ── Tracer ──

/// Provider-reported token usage observed at the end of a streamed response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamTraceUsage {
    /// Tokens consumed by the request input.
    pub input_tokens: u32,
    /// Tokens produced by the streamed response.
    pub output_tokens: u32,
    /// Tokens written to a provider prompt cache.
    pub cache_creation_input_tokens: Option<u32>,
    /// Tokens read from a provider prompt cache.
    pub cache_read_input_tokens: Option<u32>,
}

impl StreamTraceUsage {
    /// Returns total provider-reported token volume, saturating on overflow.
    #[must_use]
    pub fn total_tokens(self) -> u32 {
        self.input_tokens
            .saturating_add(self.cache_creation_input_tokens.unwrap_or(0))
            .saturating_add(self.cache_read_input_tokens.unwrap_or(0))
            .saturating_add(self.output_tokens)
    }

    /// Returns input tokens not served by a prompt-cache read.
    #[must_use]
    pub fn billable_input_tokens(self) -> u32 {
        self.input_tokens
            .saturating_add(self.cache_creation_input_tokens.unwrap_or(0))
    }
}

/// Traces requests/responses to a persistent log.
pub trait Tracer: Send + Sync {
    /// Generates a new trace identifier.
    fn new_trace_id(&self) -> String;

    /// Records a request trace entry.
    fn trace_request(
        &self,
        id: &str,
        request: &CanonicalRequest,
        provider: &str,
        route_type: &RouteType,
        is_stream: bool,
    );

    /// Records a response trace entry.
    fn trace_response(&self, id: &str, response: &ProviderResponse, latency_ms: u64);

    /// Records one streamed response chunk exactly as it is sent to the client.
    fn trace_stream_chunk(&self, _id: &str, _seq: u64, _chunk: &[u8]) {}

    /// Records streamed response completion.
    fn trace_stream_end(
        &self,
        _id: &str,
        _chunk_count: u64,
        _byte_count: usize,
        _latency_ms: u64,
        _status: &str,
        _usage: Option<StreamTraceUsage>,
    ) {
    }

    /// Records an error trace entry.
    fn trace_error(&self, id: &str, error: &str);

    /// Records a streaming response assembled from accumulated content blocks.
    ///
    /// `content` is the full Anthropic-shaped content array (text, `tool_use`,
    /// and thinking), so a streamed `res` trace mirrors a non-streaming one.
    /// Default no-op so non-file tracers (mocks) need not implement it.
    fn trace_response_stream(
        &self,
        _id: &str,
        _content: serde_json::Value,
        _stop_reason: &str,
        _usage: StreamTraceUsage,
        _latency_ms: u64,
    ) {
    }

    /// Returns whether tracing is active. Default `false`.
    fn is_enabled(&self) -> bool {
        false
    }
}

// ── Provider Availability ──

/// Determines whether a provider can accept requests.
#[async_trait]
pub trait ProviderAvailability: Send + Sync {
    /// Returns true if the provider is available for requests.
    async fn can_execute(&self, provider: &str) -> bool;

    /// Records a successful request to the provider, including observed latency.
    async fn record_success(&self, provider: &str, latency_ms: u64);

    /// Records a failed request to the provider.
    async fn record_failure(&self, provider: &str);

    /// Returns a snapshot of all provider states.
    async fn all_states(&self) -> HashMap<String, CircuitState>;
}

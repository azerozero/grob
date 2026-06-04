//! Central trait contracts for the dispatch pipeline.
//!
//! Defines abstractions for DLP, routing, tracing, spend tracking, audit logging,
//! event tapping, and provider availability. Concrete types implement these traits
//! in their own modules; state types can consume them as trait objects for testability.

use crate::models::{CanonicalRequest, RouteType};
use crate::providers::ProviderResponse;
use crate::security::circuit_breaker::CircuitState;
use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashMap;

// ── DLP Pipeline ──

/// Sanitizes requests and responses for data-loss prevention.
///
/// Concrete implementations scrub secrets, PII, and canary tokens from
/// outgoing requests, reverse any anonymisation on streamed responses,
/// and flag exfiltration attempts in URL payloads.
///
/// # Examples
///
/// A generic helper that uses any implementation to redact a response body:
///
/// ```no_run
/// use grob::traits::DlpPipeline;
/// use std::borrow::Cow;
///
/// fn redact<P: DlpPipeline>(pipeline: &P, response: &str) -> String {
///     let sanitized: Cow<'_, str> = pipeline.sanitize_response_text(response);
///     sanitized.into_owned()
/// }
/// ```
#[cfg(feature = "dlp")]
pub trait DlpPipeline: Send + Sync {
    /// Sanitizes an outgoing request (non-blocking, best-effort).
    fn sanitize_request(&self, request: &mut CanonicalRequest);

    /// Sanitizes a request and returns an error if blocked.
    fn sanitize_request_checked(
        &self,
        request: &mut CanonicalRequest,
    ) -> std::result::Result<
        Vec<crate::features::dlp::DlpActionReport>,
        crate::features::dlp::DlpBlockError,
    >;

    /// Sanitizes response text (de-anonymize + secret scan).
    fn sanitize_response_text<'a>(&self, text: &'a str) -> std::borrow::Cow<'a, str>;

    /// Checks response for URL exfiltration.
    fn check_response_url_exfil(
        &self,
        text: &str,
    ) -> std::result::Result<(), crate::features::dlp::DlpBlockError>;

    /// Runs end-of-stream scanning for cross-chunk secrets.
    fn scan_end_of_stream(&self, full_text: &str);

    /// Returns whether input scanning is enabled.
    fn scan_input_enabled(&self) -> bool;

    /// Returns whether output scanning is enabled.
    fn scan_output_enabled(&self) -> bool;
}

// ── Request Router ──

/// Routes requests to concrete model names based on configured rules.
///
/// Implementations inspect a [`CanonicalRequest`] (prompt patterns, tier
/// hints, explicit model aliases) and return a [`crate::models::RouteDecision`]
/// identifying the backend model that should serve the request.
///
/// # Examples
///
/// A thin wrapper that delegates to any router implementation:
///
/// ```no_run
/// use grob::traits::RequestRouter;
/// use grob::models::{CanonicalRequest, RouteDecision};
/// use anyhow::Result;
///
/// fn pick_model<R: RequestRouter>(router: &R, request: &mut CanonicalRequest) -> Result<String> {
///     let decision: RouteDecision = router.route(request)?;
///     Ok(decision.model_name)
/// }
/// ```
pub trait RequestRouter: Send + Sync {
    /// Routes a request and returns a routing decision.
    ///
    /// # Errors
    ///
    /// - Returns an error if no matching route is found or routing logic fails.
    fn route(&self, request: &mut CanonicalRequest) -> Result<crate::models::RouteDecision>;
}

// ── Tracer ──

/// Provider-reported token usage observed at the end of a streamed response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamTraceUsage {
    /// Tokens consumed by the request input.
    pub input_tokens: u32,
    /// Tokens produced by the streamed response.
    pub output_tokens: u32,
}

impl StreamTraceUsage {
    /// Returns `input_tokens + output_tokens`, saturating on overflow.
    #[must_use]
    pub fn total_tokens(self) -> u32 {
        self.input_tokens.saturating_add(self.output_tokens)
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
        _input_tokens: u32,
        _output_tokens: u32,
        _latency_ms: u64,
    ) {
    }

    /// Returns whether tracing is active. Default `false`.
    fn is_enabled(&self) -> bool {
        false
    }
}

// ── Spend Tracking ──

/// Tracks provider spend with budget enforcement.
pub trait SpendTracking: Send {
    /// Records a cost entry for a provider/model pair.
    fn record(&mut self, provider: &str, model: &str, cost: f64);

    /// Records a cost entry scoped to a tenant.
    fn record_tenant(&mut self, tenant: &str, provider: &str, model: &str, cost: f64);

    /// Checks budget limits and returns an error if exceeded.
    fn check_budget(
        &self,
        provider: &str,
        model: &str,
        global_limit: f64,
        provider_limit: Option<f64>,
        model_limit: Option<f64>,
    ) -> std::result::Result<(), crate::features::token_pricing::spend::BudgetError>;

    /// Checks per-tenant budget limits.
    ///
    /// Default implementation delegates to [`Self::check_budget`] so test
    /// mocks remain a no-op; production [`SpendTracker`](crate::features::token_pricing::spend::SpendTracker)
    /// overrides this to enforce per-tenant isolation.
    fn check_tenant_budget(
        &self,
        _tenant: Option<&str>,
        provider: &str,
        model: &str,
        tenant_limit: f64,
        provider_limit: Option<f64>,
        model_limit: Option<f64>,
    ) -> std::result::Result<(), crate::features::token_pricing::spend::BudgetError> {
        self.check_budget(provider, model, tenant_limit, provider_limit, model_limit)
    }

    /// Returns the total spend for the current period.
    fn total(&self) -> f64;

    /// Persists the current spend data.
    fn save(&self);

    /// Returns per-provider spend breakdown (name, spend_usd, request_count).
    fn provider_breakdown(&self) -> Vec<(String, f64, u64)> {
        Vec::new()
    }

    /// Checks budget limits and returns a warning message if approaching limits.
    fn check_warnings(
        &self,
        provider: &str,
        model: &str,
        limits: &crate::features::token_pricing::spend::BudgetLimits,
    ) -> Option<String>;
}

// ── Audit Writer ──

/// Writes signed, hash-chained audit log entries.
#[cfg(feature = "compliance")]
pub trait AuditWriter: Send + Sync {
    /// Writes a single audit entry.
    ///
    /// # Errors
    ///
    /// - Returns an error if the audit entry cannot be written to the log.
    fn write(&self, entry: crate::security::audit_log::AuditEntry) -> Result<()>;
}

// ── Event Tap ──

/// Sends events to an external tap/webhook (non-blocking).
#[cfg(feature = "tap")]
pub trait EventTap: Send + Sync {
    /// Attempts to send an event without blocking.
    fn try_send(&self, event: crate::features::tap::TapEvent);
}

// ── Provider Availability ──

/// Determines whether a provider can accept requests.
#[async_trait]
pub trait ProviderAvailability: Send + Sync {
    /// Returns true if the provider is available for requests.
    async fn can_execute(&self, provider: &str) -> bool;

    /// Records a successful request to the provider.
    async fn record_success(&self, provider: &str);

    /// Records a failed request to the provider.
    async fn record_failure(&self, provider: &str);

    /// Returns a snapshot of all provider states.
    async fn all_states(&self) -> HashMap<String, CircuitState>;
}

// ── Test Mocks ──

#[cfg(any(test, feature = "test-util"))]
pub mod mocks {
    use super::*;

    /// Mock router that always returns a fixed decision.
    pub struct MockRouter {
        pub model_name: String,
    }

    impl RequestRouter for MockRouter {
        fn route(&self, _request: &mut CanonicalRequest) -> Result<crate::models::RouteDecision> {
            Ok(crate::models::RouteDecision {
                model_name: self.model_name.clone(),
                route_type: RouteType::Default,
                matched_prompt: None,
                complexity_tier: None,
            })
        }
    }

    /// Mock tracer that records nothing.
    pub struct MockTracer;

    impl Tracer for MockTracer {
        fn new_trace_id(&self) -> String {
            String::new()
        }

        fn trace_request(
            &self,
            _id: &str,
            _request: &CanonicalRequest,
            _provider: &str,
            _route_type: &RouteType,
            _is_stream: bool,
        ) {
        }

        fn trace_response(&self, _id: &str, _response: &ProviderResponse, _latency_ms: u64) {}

        fn trace_error(&self, _id: &str, _error: &str) {}
    }

    /// Mock availability that always permits execution.
    pub struct MockAvailability;

    #[async_trait]
    impl ProviderAvailability for MockAvailability {
        async fn can_execute(&self, _provider: &str) -> bool {
            true
        }

        async fn record_success(&self, _provider: &str) {}

        async fn record_failure(&self, _provider: &str) {}

        async fn all_states(&self) -> HashMap<String, CircuitState> {
            HashMap::new()
        }
    }

    /// Mock spend tracker that accumulates nothing and never exceeds budget.
    pub struct MockSpendTracking;

    impl SpendTracking for MockSpendTracking {
        fn record(&mut self, _provider: &str, _model: &str, _cost: f64) {}
        fn record_tenant(&mut self, _tenant: &str, _provider: &str, _model: &str, _cost: f64) {}
        fn check_budget(
            &self,
            _provider: &str,
            _model: &str,
            _global: f64,
            _provider_limit: Option<f64>,
            _model_limit: Option<f64>,
        ) -> std::result::Result<(), crate::features::token_pricing::spend::BudgetError> {
            Ok(())
        }
        fn total(&self) -> f64 {
            0.0
        }
        fn provider_breakdown(&self) -> Vec<(String, f64, u64)> {
            vec![]
        }
        fn save(&self) {}
        fn check_warnings(
            &self,
            _provider: &str,
            _model: &str,
            _limits: &crate::features::token_pricing::spend::BudgetLimits,
        ) -> Option<String> {
            None
        }
    }

    /// Mock DLP pipeline that passes all content unchanged.
    #[cfg(feature = "dlp")]
    pub struct MockDlpPipeline;

    #[cfg(feature = "dlp")]
    impl DlpPipeline for MockDlpPipeline {
        fn sanitize_request(&self, _request: &mut CanonicalRequest) {}
        fn sanitize_request_checked(
            &self,
            _request: &mut CanonicalRequest,
        ) -> std::result::Result<
            Vec<crate::features::dlp::DlpActionReport>,
            crate::features::dlp::DlpBlockError,
        > {
            Ok(vec![])
        }
        fn sanitize_response_text<'a>(&self, text: &'a str) -> std::borrow::Cow<'a, str> {
            std::borrow::Cow::Borrowed(text)
        }
        fn check_response_url_exfil(
            &self,
            _text: &str,
        ) -> std::result::Result<(), crate::features::dlp::DlpBlockError> {
            Ok(())
        }
        fn scan_end_of_stream(&self, _full_text: &str) {}
        fn scan_input_enabled(&self) -> bool {
            false
        }
        fn scan_output_enabled(&self) -> bool {
            false
        }
    }

    /// Mock audit writer that discards all entries.
    #[cfg(feature = "compliance")]
    pub struct MockAuditWriter;

    #[cfg(feature = "compliance")]
    impl AuditWriter for MockAuditWriter {
        fn write(&self, _entry: crate::security::audit_log::AuditEntry) -> Result<()> {
            Ok(())
        }
    }

    /// Mock event tap that drops all events.
    #[cfg(feature = "tap")]
    pub struct MockEventTap;

    #[cfg(feature = "tap")]
    impl EventTap for MockEventTap {
        fn try_send(&self, _event: crate::features::tap::TapEvent) {}
    }
}

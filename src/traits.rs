//! Central trait contracts for the dispatch pipeline.
//!
//! Defines abstractions for DLP, routing, tracing, spend tracking, audit logging,
//! event tapping, and provider availability. Concrete types implement these traits
//! in their own modules; state types can consume them as trait objects for testability.

use crate::models::{AnthropicRequest, RouteType};
use crate::providers::ProviderResponse;
use crate::security::circuit_breaker::CircuitState;
use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashMap;

// ── DLP Pipeline ──

/// Sanitization pipeline for data loss prevention.
#[cfg(feature = "dlp")]
pub trait DlpPipeline: Send + Sync {
    /// Sanitizes an outgoing request (non-blocking, best-effort).
    fn sanitize_request(&self, request: &mut AnthropicRequest);

    /// Sanitizes a request and returns an error if blocked.
    fn sanitize_request_checked(
        &self,
        request: &mut AnthropicRequest,
    ) -> std::result::Result<(), crate::features::dlp::DlpBlockError>;

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

/// Routes requests to model names based on rules.
pub trait RequestRouter: Send + Sync {
    /// Routes a request and returns a routing decision.
    fn route(&self, request: &mut AnthropicRequest) -> Result<crate::models::RouteDecision>;
}

// ── Tracer ──

/// Traces requests/responses to a persistent log.
pub trait Tracer: Send + Sync {
    /// Generates a new trace identifier.
    fn new_trace_id(&self) -> String;

    /// Records a request trace entry.
    fn trace_request(
        &self,
        id: &str,
        request: &AnthropicRequest,
        provider: &str,
        route_type: &RouteType,
        is_stream: bool,
    );

    /// Records a response trace entry.
    fn trace_response(&self, id: &str, response: &ProviderResponse, latency_ms: u64);

    /// Records an error trace entry.
    fn trace_error(&self, id: &str, error: &str);
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

    /// Returns the total spend for the current period.
    fn total(&self) -> f64;

    /// Persists the current spend data.
    fn save(&self);

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

#[cfg(test)]
pub mod mocks {
    use super::*;

    /// Mock router that always returns a fixed decision.
    pub struct MockRouter {
        pub model_name: String,
    }

    impl RequestRouter for MockRouter {
        fn route(&self, _request: &mut AnthropicRequest) -> Result<crate::models::RouteDecision> {
            Ok(crate::models::RouteDecision {
                model_name: self.model_name.clone(),
                route_type: RouteType::Default,
                matched_prompt: None,
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
            _request: &AnthropicRequest,
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
}

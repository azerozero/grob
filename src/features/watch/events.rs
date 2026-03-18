//! Event types broadcast by the live event bus.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Events emitted by the dispatch pipeline for live observation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WatchEvent {
    /// A request entered the dispatch pipeline.
    RequestStart {
        /// Correlation identifier for this request.
        request_id: String,
        /// Model name targeted by the request.
        model: String,
        /// Provider handling this attempt.
        provider: String,
        /// Estimated input token count.
        input_tokens: u32,
        /// Routing classification (think, websearch, background, default).
        route_type: String,
        /// When the request was received.
        timestamp: DateTime<Utc>,
    },
    /// A request completed successfully.
    RequestEnd {
        /// Correlation identifier for this request.
        request_id: String,
        /// Model that generated the response.
        model: String,
        /// Provider that served the response.
        provider: String,
        /// Output tokens generated.
        output_tokens: u32,
        /// End-to-end latency in milliseconds.
        latency_ms: u64,
        /// Estimated cost in USD.
        cost_usd: f64,
        /// When the response completed.
        timestamp: DateTime<Utc>,
    },
    /// A request failed at a provider.
    RequestError {
        /// Correlation identifier for this request.
        request_id: String,
        /// Model that was attempted.
        model: String,
        /// Provider that returned the error.
        provider: String,
        /// Human-readable error description.
        error: String,
        /// When the error occurred.
        timestamp: DateTime<Utc>,
    },
    /// DLP engine took action on a request or response.
    DlpAction {
        /// Correlation identifier for the owning request.
        request_id: String,
        /// Whether this scanned the request or response.
        direction: DlpDirection,
        /// Action taken (redact, block, warn).
        action: String,
        /// Rule category that triggered (secret, pii, injection, url_exfil).
        rule_type: String,
        /// Human-readable detail about what was detected.
        detail: String,
        /// When the action was taken.
        timestamp: DateTime<Utc>,
    },
    /// A provider failover occurred.
    Fallback {
        /// Correlation identifier for the owning request.
        request_id: String,
        /// Provider that failed.
        from_provider: String,
        /// Provider being tried next.
        to_provider: String,
        /// Why the failover happened.
        reason: String,
        /// When the failover occurred.
        timestamp: DateTime<Utc>,
    },
    /// Circuit breaker state changed.
    CircuitBreaker {
        /// Provider whose circuit breaker changed.
        provider: String,
        /// New state (closed, open, half_open).
        state: String,
        /// When the state change occurred.
        timestamp: DateTime<Utc>,
    },
    /// Provider health snapshot (emitted periodically).
    ProviderHealth {
        /// Provider being reported on.
        provider: String,
        /// Latest observed latency in milliseconds.
        latency_ms: u64,
        /// Rolling success rate (0.0–100.0).
        success_rate: f64,
        /// Total requests served by this provider.
        requests_total: u64,
        /// When this snapshot was taken.
        timestamp: DateTime<Utc>,
    },
}

/// Direction of DLP scanning.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DlpDirection {
    /// Scanning the outbound request to the provider.
    Request,
    /// Scanning the inbound response from the provider.
    Response,
}

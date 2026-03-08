//! Provider-specific request extensions carried through the canonical pipeline.
//!
//! Fields that exist in one provider's API but not in the canonical request
//! are captured here during inbound transformation and restored during outbound
//! transformation, enabling lossless roundtrips (e.g. OpenAI → Canonical → OpenAI).

/// Provider-specific fields that travel alongside [`super::CanonicalRequest`].
///
/// Skipped during JSON serialization — these are in-memory metadata only.
#[derive(Debug, Clone, Default)]
pub struct RequestExtensions {
    // ── Anthropic ──
    /// Client-provided beta feature flags forwarded to Anthropic.
    pub client_beta: Option<String>,

    // ── OpenAI ──
    /// Structured output format (e.g. `json_schema`, `json_object`).
    pub response_format: Option<serde_json::Value>,
    /// Reasoning effort hint (`"low"`, `"medium"`, `"high"`).
    pub reasoning_effort: Option<String>,
    /// Deterministic sampling seed.
    pub seed: Option<u64>,
    /// Penalises tokens by their existing frequency in the text.
    pub frequency_penalty: Option<f64>,
    /// Penalises tokens that have already appeared at all.
    pub presence_penalty: Option<f64>,
    /// Allows the model to call multiple tools in one turn.
    pub parallel_tool_calls: Option<bool>,
    /// End-user identifier for abuse monitoring.
    pub user: Option<String>,
    /// Enables per-token log-probabilities in the response.
    pub logprobs: Option<bool>,
    /// Number of most-likely tokens to return log-probabilities for.
    pub top_logprobs: Option<u32>,
    /// Requested service tier (`"auto"`, `"default"`, `"flex"`).
    pub service_tier: Option<String>,
}

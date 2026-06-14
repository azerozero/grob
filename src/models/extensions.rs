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
    /// Optional author name for the hoisted OpenAI system message.
    pub openai_system_name: Option<String>,
    /// Optional author names for canonical messages, indexed by message position.
    pub openai_message_names: Vec<Option<String>>,

    /// Verbatim Responses-API request body from a native client (Codex CLI).
    ///
    /// When set, the OpenAI Responses backend forwards this body unchanged
    /// (only the `model` is swapped to the resolved upstream model) instead of
    /// rebuilding it from the canonical request. Round-tripping flattens typed
    /// `input` content, reorders the `tools` shape, and replaces the client's
    /// `prompt_cache_key` — all of which change the token prefix and defeat the
    /// backend's prompt cache (gpt-5.5 returns zero cached tokens). Forwarding
    /// the exact bytes keeps the cache warm.
    pub responses_passthrough_body: Option<serde_json::Value>,

    /// Set when the request was translated from a non-Anthropic client
    /// (OpenAI/Codex), which has no `cache_control` concept. The Anthropic
    /// provider then injects an ephemeral `cache_control` breakpoint on the
    /// system prefix so the large stable prompt is cached instead of re-billed
    /// every turn. Left `false` for Anthropic-native clients, which manage their
    /// own breakpoints.
    pub inject_anthropic_cache: bool,

    // Routing hints.
    /// Set when the request originates from the Codex CLI (Responses API).
    ///
    /// Codex's own `instructions` ARE the authoritative Codex agent prompt, so
    /// the OpenAI Responses transform forwards them as the top-level
    /// `instructions` (keeping the backend in full agentic mode) instead of
    /// swapping in the minimal tool-deferring preamble used for foreign clients.
    pub codex_native: bool,
}

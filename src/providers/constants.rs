/// Anthropic Messages API version header value.
pub const ANTHROPIC_API_VERSION: &str = "2023-06-01";
/// Comma-separated beta feature flags for Anthropic API requests.
pub const ANTHROPIC_BETA_FEATURES: &str = "oauth-2025-04-20,claude-code-20250219,interleaved-thinking-2025-05-14,fine-grained-tool-streaming-2025-05-14,prompt-caching-scope-2026-01-05";
/// Domain substring used to identify Anthropic backend URLs.
pub const ANTHROPIC_DOMAIN: &str = "anthropic.com";
/// Minimum length for a valid Anthropic webhook signature.
pub const MIN_ANTHROPIC_SIGNATURE_LENGTH: usize = 100;
/// Token-remaining threshold that triggers a rate-limit warning.
pub const RATE_LIMIT_TOKENS_LOW: u64 = 10_000;
/// Request-remaining threshold that triggers a rate-limit warning.
pub const RATE_LIMIT_REQUESTS_LOW: u64 = 10;
/// Approximate characters per token for heuristic estimation.
pub const CHARS_PER_TOKEN: usize = 4;

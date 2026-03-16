//! OpenAI Responses API (`/v1/responses`) compatibility layer.
//!
//! Translates between the Responses wire format (used by Codex CLI, OpenAI SDK)
//! and grob's canonical Anthropic-based request/response model.
//! Streaming uses named SSE events (e.g. `event: response.output_text.delta`).

/// SSE stream adapter: Anthropic SSE → Responses named-event SSE.
pub mod stream;
/// Bidirectional request/response transformation.
pub mod transform;
/// Request and response type definitions.
pub mod types;

pub use stream::AnthropicToResponsesStream;
pub use transform::{transform_canonical_to_responses, transform_responses_to_canonical};
pub use types::{ResponsesRequest, ResponsesResponse};

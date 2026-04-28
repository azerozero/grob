//! Stateless complexity classifier for request routing.
//!
//! Assigns a [`ComplexityTier`] (trivial / medium / complex) to each
//! incoming request based on a weighted sum of observable signals.
//! The tier feeds into the provider-selection pipeline: lighter requests
//! can be routed to cheaper models, heavier ones to capable tiers.
//!
//! See `docs/how-to/auto-tune-routing.md` for tuning weights from trace data.

use crate::models::{CanonicalRequest, MessageContent};

/// Complexity tier assigned by the heuristic scorer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ComplexityTier {
    /// Short answer, lookup, simple generation.
    Trivial,
    /// Standard reasoning, moderate context.
    Medium,
    /// Deep reasoning, tool use, large context.
    Complex,
}

impl std::fmt::Display for ComplexityTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComplexityTier::Trivial => f.write_str("trivial"),
            ComplexityTier::Medium => f.write_str("medium"),
            ComplexityTier::Complex => f.write_str("complex"),
        }
    }
}

/// Configurable weights for each scoring signal.
///
/// All weights default to `1.0`. Set a weight to `0.0` to disable
/// the corresponding signal entirely.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ScoringWeights {
    /// Weight for the max_tokens signal.
    pub max_tokens: f32,
    /// Weight for the tool/tool_use presence signal.
    pub tools: f32,
    /// Weight for the context size (message count + estimated tokens) signal.
    pub context_size: f32,
    /// Weight for keyword detection in the prompt.
    pub keywords: f32,
    /// Weight for long system prompt detection.
    pub system_prompt: f32,
}

impl Default for ScoringWeights {
    fn default() -> Self {
        Self {
            max_tokens: 1.0,
            tools: 1.0,
            context_size: 1.0,
            keywords: 1.0,
            system_prompt: 1.0,
        }
    }
}

/// Thresholds that map the weighted score to a tier.
///
/// `score < medium_threshold` → Trivial
/// `score < complex_threshold` → Medium
/// otherwise → Complex
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ScoringThresholds {
    /// Score below which the request is considered trivial.
    pub medium_threshold: f32,
    /// Score at or above which the request is considered complex.
    pub complex_threshold: f32,
}

impl Default for ScoringThresholds {
    fn default() -> Self {
        Self {
            medium_threshold: 2.0,
            complex_threshold: 5.0,
        }
    }
}

/// Scoring configuration combining weights and thresholds.
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScoringConfig {
    /// Per-signal weights.
    pub weights: ScoringWeights,
    /// Tier boundary thresholds.
    pub thresholds: ScoringThresholds,
}

// ── Signal scoring functions ─────────────────────────────────────────

/// Scores the `max_tokens` field.
///
/// - < 500 → 0 (trivial range)
/// - 500..4000 → 1 (medium range)
/// - >= 4000 → 3 (complex range)
#[inline]
fn score_max_tokens(max_tokens: u32) -> f32 {
    if max_tokens < 500 {
        0.0
    } else if max_tokens < 4000 {
        1.0
    } else {
        3.0
    }
}

/// Scores tool/tool_use presence.
///
/// Any tools defined → 3 (complex signal).
#[inline]
fn score_tools(request: &CanonicalRequest) -> f32 {
    match request.tools.as_ref() {
        Some(tools) if !tools.is_empty() => 3.0,
        _ => 0.0,
    }
}

/// Rough token estimate: ~4 chars per token (conservative, no tokenizer needed).
#[inline]
fn estimate_tokens(text: &str) -> usize {
    text.len() / 4
}

/// Scores context size from message count and estimated total tokens.
///
/// - <= 2 messages AND < 500 estimated tokens → 0
/// - <= 10 messages AND < 4000 estimated tokens → 1
/// - otherwise → 3
#[inline]
fn score_context_size(request: &CanonicalRequest) -> f32 {
    let msg_count = request.messages.len();
    let total_chars: usize = request
        .messages
        .iter()
        .map(|m| match &m.content {
            MessageContent::Text(t) => t.len(),
            MessageContent::Blocks(blocks) => blocks
                .iter()
                .filter_map(|b| b.as_text())
                .map(|t| t.len())
                .sum(),
        })
        .sum();
    let est_tokens = estimate_tokens_from_chars(total_chars);

    if msg_count <= 2 && est_tokens < 500 {
        0.0
    } else if msg_count <= 10 && est_tokens < 4000 {
        1.0
    } else {
        3.0
    }
}

/// Approximates token count by dividing character count by 4 (BPE heuristic for English prose).
#[inline]
pub(crate) fn estimate_tokens_from_chars(chars: usize) -> usize {
    chars / 4
}

/// Complexity-indicating keywords (lowercased for case-insensitive matching).
const COMPLEX_KEYWORDS: &[&str] = &[
    "refactor",
    "architect",
    "redesign",
    "migrate",
    "implement",
    "optimize",
];

const MEDIUM_KEYWORDS: &[&str] = &["debug", "explain", "analyze", "review", "compare", "test"];

/// Scores keyword presence in the last user message.
///
/// Complex keyword → 2, medium keyword → 1, none → 0.
fn score_keywords(request: &CanonicalRequest) -> f32 {
    let text = extract_last_user_text(request);
    let text = match text {
        Some(t) => t,
        None => return 0.0,
    };
    let lower = text.to_ascii_lowercase();

    for kw in COMPLEX_KEYWORDS {
        if lower.contains(kw) {
            return 2.0;
        }
    }
    for kw in MEDIUM_KEYWORDS {
        if lower.contains(kw) {
            return 1.0;
        }
    }
    0.0
}

/// Returns the text of the most recent `user`-role message, flattening content blocks, or `None` if none has text.
pub(crate) fn extract_last_user_text(request: &CanonicalRequest) -> Option<String> {
    let last_user = request.messages.iter().rev().find(|m| m.role == "user")?;
    match &last_user.content {
        MessageContent::Text(t) => Some(t.clone()),
        MessageContent::Blocks(blocks) => {
            let text: String = blocks
                .iter()
                .filter_map(|b| b.as_text())
                .collect::<Vec<_>>()
                .join(" ");
            if text.is_empty() {
                None
            } else {
                Some(text)
            }
        }
    }
}

/// Scores system prompt length.
///
/// - No system prompt or < 500 estimated tokens → 0
/// - >= 500 estimated tokens → 2
fn score_system_prompt(request: &CanonicalRequest) -> f32 {
    let text = match &request.system {
        Some(sp) => sp.to_text(),
        None => return 0.0,
    };
    let est_tokens = estimate_tokens(&text);
    if est_tokens >= 500 {
        2.0
    } else {
        0.0
    }
}

// ── Public API ───────────────────────────────────────────────────────

/// Classifies request complexity as a pure, stateless function.
///
/// Computes a weighted sum of observable signals and maps it to a
/// [`ComplexityTier`]. Target latency: < 0.1 ms per call.
pub fn classify_complexity(request: &CanonicalRequest, config: &ScoringConfig) -> ComplexityTier {
    let w = &config.weights;

    let score = w.max_tokens * score_max_tokens(request.max_tokens)
        + w.tools * score_tools(request)
        + w.context_size * score_context_size(request)
        + w.keywords * score_keywords(request)
        + w.system_prompt * score_system_prompt(request);

    if score < config.thresholds.medium_threshold {
        ComplexityTier::Trivial
    } else if score < config.thresholds.complex_threshold {
        ComplexityTier::Medium
    } else {
        ComplexityTier::Complex
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Message, MessageContent, SystemPrompt, Tool};

    fn simple_request(text: &str, max_tokens: u32) -> CanonicalRequest {
        CanonicalRequest {
            model: "test-model".to_string(),
            messages: vec![Message {
                role: "user".to_string(),
                content: MessageContent::Text(text.to_string()),
            }],
            max_tokens,
            thinking: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop_sequences: None,
            stream: None,
            metadata: None,
            system: None,
            tools: None,
            tool_choice: None,
            extensions: Default::default(),
        }
    }

    fn default_config() -> ScoringConfig {
        ScoringConfig::default()
    }

    // ── 1. Trivial: short prompt, low max_tokens, no tools ──

    #[test]
    fn trivial_hello() {
        let req = simple_request("hello", 100);
        let tier = classify_complexity(&req, &default_config());
        assert_eq!(tier, ComplexityTier::Trivial);
    }

    #[test]
    fn trivial_short_question() {
        let req = simple_request("What is 2+2?", 50);
        let tier = classify_complexity(&req, &default_config());
        assert_eq!(tier, ComplexityTier::Trivial);
    }

    // ── 2. Medium: moderate tokens or medium keywords ──

    #[test]
    fn medium_via_max_tokens_and_keyword() {
        // max_tokens 2000 → 1 + keyword "explain" → 1 = score 2 → medium
        let req = simple_request("explain how to sort an array", 2000);
        let tier = classify_complexity(&req, &default_config());
        assert_eq!(tier, ComplexityTier::Medium);
    }

    #[test]
    fn medium_via_keyword_debug() {
        // keyword "debug" = 1, max_tokens 600 → 1 → score = 2 → medium
        let req = simple_request("debug this function please", 600);
        let tier = classify_complexity(&req, &default_config());
        assert_eq!(tier, ComplexityTier::Medium);
    }

    #[test]
    fn medium_via_keyword_explain() {
        let req = simple_request("explain how this works", 1000);
        let tier = classify_complexity(&req, &default_config());
        // keyword "explain" = 1, max_tokens 1000 → 1, context = 0 → score = 2 → medium
        assert_eq!(tier, ComplexityTier::Medium);
    }

    // ── 3. Complex: tools + high max_tokens + system prompt ──

    #[test]
    fn complex_with_tools_and_high_tokens() {
        let mut req = simple_request("help me build this", 8000);
        req.tools = Some(vec![
            make_tool("tool1"),
            make_tool("tool2"),
            make_tool("tool3"),
            make_tool("tool4"),
            make_tool("tool5"),
        ]);
        let tier = classify_complexity(&req, &default_config());
        // tools = 3, max_tokens 8000 → 3 → score = 6 >= 5 → complex
        assert_eq!(tier, ComplexityTier::Complex);
    }

    #[test]
    fn complex_system_prompt_2000_tokens_plus_tools() {
        let long_system = "x".repeat(8000); // ~2000 tokens
        let mut req = simple_request("do something", 8000);
        req.system = Some(SystemPrompt::Text(long_system));
        req.tools = Some(vec![
            make_tool("t1"),
            make_tool("t2"),
            make_tool("t3"),
            make_tool("t4"),
            make_tool("t5"),
        ]);
        let tier = classify_complexity(&req, &default_config());
        // system_prompt = 2, tools = 3, max_tokens = 3 → score = 8 → complex
        assert_eq!(tier, ComplexityTier::Complex);
    }

    // ── 4. Hint override via ComplexityTier directly ──
    // (Hint is resolved upstream in dispatch; this test validates that
    //  the scoring returns what it computes, and the caller overrides.)

    #[test]
    fn scoring_ignores_metadata_hint() {
        // classify_complexity is pure — it does not read metadata.grob_hint.
        // The dispatch layer overrides the tier; scoring always computes.
        let mut req = simple_request("architect a distributed system", 8000);
        req.tools = Some(vec![make_tool("t1")]);
        let tier = classify_complexity(&req, &default_config());
        assert_eq!(tier, ComplexityTier::Complex);
        // A caller would override: if hint == Trivial { ComplexityTier::Trivial }
    }

    // ── 5. Edge cases ──

    #[test]
    fn edge_empty_request() {
        let req = CanonicalRequest {
            model: "test".to_string(),
            messages: vec![],
            max_tokens: 0,
            thinking: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop_sequences: None,
            stream: None,
            metadata: None,
            system: None,
            tools: None,
            tool_choice: None,
            extensions: Default::default(),
        };
        let tier = classify_complexity(&req, &default_config());
        // All signals = 0 → trivial
        assert_eq!(tier, ComplexityTier::Trivial);
    }

    #[test]
    fn edge_max_tokens_zero() {
        let req = simple_request("hello", 0);
        let tier = classify_complexity(&req, &default_config());
        assert_eq!(tier, ComplexityTier::Trivial);
    }

    #[test]
    fn edge_empty_tools_array() {
        let mut req = simple_request("hello", 100);
        req.tools = Some(vec![]);
        let tier = classify_complexity(&req, &default_config());
        // Empty tools array should not trigger tool signal
        assert_eq!(tier, ComplexityTier::Trivial);
    }

    // ── 6. Weight configuration ──

    #[test]
    fn custom_weights_disable_tools_signal() {
        let mut cfg = default_config();
        cfg.weights.tools = 0.0;
        let mut req = simple_request("hello", 100);
        req.tools = Some(vec![make_tool("t1")]);
        let tier = classify_complexity(&req, &cfg);
        // tools signal disabled → score stays trivial
        assert_eq!(tier, ComplexityTier::Trivial);
    }

    #[test]
    fn custom_thresholds() {
        let mut cfg = default_config();
        cfg.thresholds.medium_threshold = 0.5;
        cfg.thresholds.complex_threshold = 1.5;
        // keyword "debug" = 1 → score 1 ∈ [0.5, 1.5) → medium
        let req = simple_request("debug this", 100);
        let tier = classify_complexity(&req, &cfg);
        assert_eq!(tier, ComplexityTier::Medium);
    }

    // ── 7. Complex keywords ──

    #[test]
    fn complex_keyword_refactor() {
        // "refactor" = 2, max_tokens 4000 → 3 → score = 5 → complex
        let req = simple_request("refactor the auth module", 4000);
        let tier = classify_complexity(&req, &default_config());
        assert_eq!(tier, ComplexityTier::Complex);
    }

    // ── 8. Large context ──

    #[test]
    fn large_context_many_messages() {
        let mut req = simple_request("summarize", 100);
        // 15 messages → context_size = 3 (> 10 messages), score = 3 → medium
        req.messages = (0..15)
            .map(|i| Message {
                role: if i % 2 == 0 { "user" } else { "assistant" }.to_string(),
                content: MessageContent::Text("some conversation text here".to_string()),
            })
            .collect();
        let tier = classify_complexity(&req, &default_config());
        assert_eq!(tier, ComplexityTier::Medium);
    }

    // ── 9. Display impl ──

    #[test]
    fn display_tiers() {
        assert_eq!(ComplexityTier::Trivial.to_string(), "trivial");
        assert_eq!(ComplexityTier::Medium.to_string(), "medium");
        assert_eq!(ComplexityTier::Complex.to_string(), "complex");
    }

    // ── 10. System prompt blocks format ──

    #[test]
    fn system_prompt_blocks_scored() {
        use crate::models::SystemBlock;
        let mut req = simple_request("hello", 100);
        let long_text = "y".repeat(4000); // ~1000 tokens
        req.system = Some(SystemPrompt::Blocks(vec![SystemBlock {
            r#type: "text".to_string(),
            text: long_text,
            cache_control: None,
        }]));
        let tier = classify_complexity(&req, &default_config());
        // system_prompt = 2 → score = 2 → medium
        assert_eq!(tier, ComplexityTier::Medium);
    }

    // ── helpers ──

    fn make_tool(name: &str) -> Tool {
        Tool {
            r#type: Some("function".to_string()),
            name: Some(name.to_string()),
            description: Some("A test tool".to_string()),
            input_schema: None,
        }
    }
}

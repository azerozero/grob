//! Reasoning-effort translation between the Codex and Anthropic vocabularies.
//!
//! Codex (`reasoning.effort`) accepts `minimal` < `low` < `medium` < `high` <
//! `xhigh` on the gpt-5 line; the gpt-6 line adds `max` and `ultra`. Anthropic
//! (`output_config.effort`) accepts `low` < `medium` < `high` < `xhigh` < `max`
//! on Opus/Sonnet 4.6+ and the whole Claude 5 family. The middle of both
//! scales is shared, so each direction is a clamp at the ends, not a table.

/// Returns the Codex `reasoning.effort` to send for `effort` on `model`.
///
/// The gpt-5 line rejects `max` and `ultra` with a 400, so both clamp to
/// `xhigh` there. Every other model takes the value verbatim, which keeps new
/// tiers usable without a grob release.
pub fn to_codex(model: &str, effort: &str) -> String {
    let clamp =
        model.to_ascii_lowercase().starts_with("gpt-5") && matches!(effort, "max" | "ultra");
    if clamp { "xhigh" } else { effort }.to_string()
}

/// Returns the Anthropic `output_config.effort` for a Codex-vocabulary `effort`.
pub fn to_anthropic(effort: &str) -> &str {
    match effort {
        "minimal" => "low",
        "ultra" => "max",
        other => other,
    }
}

/// Returns whether `model` accepts `output_config.effort`.
///
/// Effort shipped with Opus/Sonnet 4.6 and is on every Claude 5 model. The
/// 4.5 and earlier generations (`claude-haiku-4-5`, `claude-opus-4-1`, Claude
/// 3.x, dated `claude-sonnet-4-2025…` ids) reject it with a 400.
pub fn anthropic_supports_effort(model: &str) -> bool {
    let mut versions = model.split('-').filter_map(|s| s.parse::<u32>().ok());
    match (versions.next(), versions.next()) {
        (Some(major), _) if major >= 5 => true,
        // A date suffix (`-20250514`) is not a minor version.
        (Some(4), Some(minor)) => (6..100).contains(&minor),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gpt5_clamps_to_xhigh_and_gpt6_passes_through() {
        assert_eq!(to_codex("gpt-5.5", "ultra"), "xhigh");
        assert_eq!(to_codex("gpt-5.4-mini", "max"), "xhigh");
        assert_eq!(to_codex("gpt-5.5", "high"), "high");
        assert_eq!(to_codex("gpt-6-astra", "ultra"), "ultra");
        assert_eq!(to_codex("gpt-6.1-sol", "max"), "max");
    }

    #[test]
    fn anthropic_vocabulary_clamps_both_ends() {
        assert_eq!(to_anthropic("minimal"), "low");
        assert_eq!(to_anthropic("ultra"), "max");
        assert_eq!(to_anthropic("xhigh"), "xhigh");
    }

    #[test]
    fn effort_support_follows_the_model_generation() {
        for yes in [
            "claude-fable-5-1",
            "claude-opus-5",
            "claude-sonnet-5-5",
            "claude-haiku-5-5",
            "claude-opus-4-6",
            "claude-opus-4-7-20260301",
            "claude-sonnet-4-8",
        ] {
            assert!(anthropic_supports_effort(yes), "{yes}");
        }
        for no in [
            "claude-haiku-4-5",
            "claude-sonnet-4-5-20250929",
            "claude-opus-4-1",
            "claude-sonnet-4-20250514",
            "claude-3-5-haiku",
        ] {
            assert!(!anthropic_supports_effort(no), "{no}");
        }
    }
}

//! Static capability map: determines whether a provider/model supports tools.

use super::config::ToolLayerConfig;

/// Built-in model prefixes known to lack tool-use support.
const NO_TOOL_PREFIXES: &[&str] = &[
    "o1",         // OpenAI o1 (no function calling)
    "o1-mini",    // OpenAI o1-mini
    "o1-preview", // OpenAI o1-preview
];

/// Returns `true` when tool injection should be blocked for this provider/model.
///
/// Checks both the built-in deny list and any user-configured overrides in
/// `config.capabilities`.
pub fn should_block_tools(config: &ToolLayerConfig, provider: &str, model: &str) -> bool {
    let model_lower = model.to_lowercase();

    // Check user-configured capability overrides first.
    if let Some(cap) = config.capabilities.get(provider) {
        if !cap.tools_supported {
            return true;
        }
        if cap
            .no_tool_models
            .iter()
            .any(|prefix| model_lower.starts_with(&prefix.to_lowercase()))
        {
            return true;
        }
    }

    // Fall back to the built-in deny list.
    NO_TOOL_PREFIXES
        .iter()
        .any(|prefix| model_lower.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_config() -> ToolLayerConfig {
        ToolLayerConfig::default()
    }

    #[test]
    fn blocks_o1_models() {
        let cfg = empty_config();
        assert!(should_block_tools(&cfg, "openai", "o1-preview-2024"));
        assert!(should_block_tools(&cfg, "openai", "o1-mini"));
    }

    #[test]
    fn allows_normal_models() {
        let cfg = empty_config();
        assert!(!should_block_tools(&cfg, "openai", "gpt-4o"));
        assert!(!should_block_tools(&cfg, "anthropic", "claude-sonnet-4-6"));
    }

    #[test]
    fn respects_config_override() {
        let mut cfg = empty_config();
        cfg.capabilities.insert(
            "custom".to_string(),
            super::super::config::CapabilityEntry {
                tools_supported: false,
                no_tool_models: vec![],
            },
        );
        assert!(should_block_tools(&cfg, "custom", "any-model"));
    }
}

//! Universal Tool Layer: injects, aliases, and gates tool definitions.
//!
//! Sits between DLP scanning and cache lookup in the dispatch pipeline.
//! When disabled (`enabled = false`), the layer is a zero-cost no-op.

pub mod aliasing;
pub mod capability;
pub mod catalog;
pub mod config;
pub mod injection;

use config::ToolLayerConfig;

/// Orchestrates tool aliasing, capability gating, and injection.
#[derive(Debug, Clone)]
pub struct ToolLayer {
    /// Parsed configuration snapshot.
    pub config: ToolLayerConfig,
}

impl ToolLayer {
    /// Creates a new tool layer from the given configuration.
    pub fn new(config: ToolLayerConfig) -> Self {
        Self { config }
    }

    /// Applies the full tool-layer pipeline to a request.
    ///
    /// Steps executed in order:
    /// 1. **Capability gate** — strips all tools if the target model lacks support.
    /// 2. **Aliasing** — rewrites alternative tool names to canonical form.
    /// 3. **Injection** — adds missing tools from the embedded catalog.
    pub fn process(
        &self,
        request: &mut crate::models::CanonicalRequest,
        provider: &str,
        model: &str,
    ) {
        if !self.config.enabled {
            return;
        }

        // Step 1: block tools entirely for models that don't support them.
        if capability::should_block_tools(&self.config, provider, model) {
            if request.tools.is_some() {
                tracing::info!(
                    provider,
                    model,
                    "Tool layer: stripped tools (model lacks tool support)"
                );
                request.tools = None;
                request.tool_choice = None;
            }
            return;
        }

        // Step 2: resolve aliases before injection (so injection sees canonical names).
        aliasing::apply_aliases(&self.config.aliases, request);

        // Step 3: inject missing tools from catalog.
        injection::inject_tools(&self.config.inject, request);
    }
}

/// Shared test helpers for submodule tests.
#[cfg(test)]
pub(crate) mod tests {
    use crate::models::{extensions::RequestExtensions, CanonicalRequest, Tool};

    /// Builds a minimal `CanonicalRequest` with the given tool names.
    pub fn make_request(tool_names: &[&str]) -> CanonicalRequest {
        let tools: Vec<Tool> = tool_names
            .iter()
            .map(|name| Tool {
                r#type: Some("function".to_string()),
                name: Some(name.to_string()),
                description: Some(format!("Client-provided {name}")),
                input_schema: None,
            })
            .collect();

        CanonicalRequest {
            model: "test-model".to_string(),
            messages: vec![],
            max_tokens: 1024,
            thinking: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop_sequences: None,
            stream: None,
            metadata: None,
            system: None,
            tools: if tools.is_empty() { None } else { Some(tools) },
            tool_choice: None,
            extensions: RequestExtensions::default(),
        }
    }

    #[test]
    fn test_alias_bash_resolves_execute_command() {
        use super::config::{AliasRule, ToolLayerConfig};
        use super::ToolLayer;

        let config = ToolLayerConfig {
            enabled: true,
            capabilities: Default::default(),
            inject: vec![],
            aliases: vec![AliasRule {
                from: "execute_command".to_string(),
                to: "bash".to_string(),
            }],
        };
        let layer = ToolLayer::new(config);
        let mut req = make_request(&["execute_command"]);

        layer.process(&mut req, "anthropic", "claude-sonnet-4-6");

        assert_eq!(req.tools.as_ref().unwrap()[0].name.as_deref(), Some("bash"));
    }

    #[test]
    fn test_inject_web_search_if_absent() {
        use super::config::{InjectRule, ToolLayerConfig};
        use super::ToolLayer;

        let config = ToolLayerConfig {
            enabled: true,
            capabilities: Default::default(),
            inject: vec![InjectRule {
                tool: "web_search".to_string(),
                if_absent: true,
            }],
            aliases: vec![],
        };
        let layer = ToolLayer::new(config);
        let mut req = make_request(&["bash"]);

        layer.process(&mut req, "anthropic", "claude-sonnet-4-6");

        let names: Vec<_> = req
            .tools
            .as_ref()
            .unwrap()
            .iter()
            .filter_map(|t| t.name.as_deref())
            .collect();
        assert!(names.contains(&"web_search"));
        assert!(names.contains(&"bash"));
    }

    #[test]
    fn test_inject_does_not_overwrite_existing() {
        use super::config::{InjectRule, ToolLayerConfig};
        use super::ToolLayer;

        let config = ToolLayerConfig {
            enabled: true,
            capabilities: Default::default(),
            inject: vec![InjectRule {
                tool: "bash".to_string(),
                if_absent: true,
            }],
            aliases: vec![],
        };
        let layer = ToolLayer::new(config);
        let mut req = make_request(&["bash"]);

        layer.process(&mut req, "anthropic", "claude-sonnet-4-6");

        let bash_count = req
            .tools
            .as_ref()
            .unwrap()
            .iter()
            .filter(|t| t.name.as_deref() == Some("bash"))
            .count();
        assert_eq!(bash_count, 1);
        // Client description preserved, not overwritten by catalog.
        assert_eq!(
            req.tools.as_ref().unwrap()[0].description.as_deref(),
            Some("Client-provided bash")
        );
    }

    #[test]
    fn test_capability_map_blocks_injection_for_no_tool_support() {
        use super::config::{CapabilityEntry, InjectRule, ToolLayerConfig};
        use super::ToolLayer;
        use std::collections::HashMap;

        let mut caps = HashMap::new();
        caps.insert(
            "custom_provider".to_string(),
            CapabilityEntry {
                tools_supported: false,
                no_tool_models: vec![],
            },
        );

        let config = ToolLayerConfig {
            enabled: true,
            capabilities: caps,
            inject: vec![InjectRule {
                tool: "bash".to_string(),
                if_absent: true,
            }],
            aliases: vec![],
        };
        let layer = ToolLayer::new(config);
        let mut req = make_request(&["bash"]);

        layer.process(&mut req, "custom_provider", "some-model");

        // Tools should be stripped entirely.
        assert!(req.tools.is_none());
    }

    #[test]
    fn test_aliasing_preserves_tool_args() {
        use super::config::{AliasRule, ToolLayerConfig};
        use super::ToolLayer;
        use crate::models::Tool;

        let config = ToolLayerConfig {
            enabled: true,
            capabilities: Default::default(),
            inject: vec![],
            aliases: vec![AliasRule {
                from: "execute_command".to_string(),
                to: "bash".to_string(),
            }],
        };
        let layer = ToolLayer::new(config);

        let schema =
            serde_json::json!({"type": "object", "properties": {"cmd": {"type": "string"}}});
        let mut req = make_request(&[]);
        req.tools = Some(vec![Tool {
            r#type: Some("function".to_string()),
            name: Some("execute_command".to_string()),
            description: Some("Custom runner".to_string()),
            input_schema: Some(schema.clone()),
        }]);

        layer.process(&mut req, "anthropic", "claude-sonnet-4-6");

        let tool = &req.tools.as_ref().unwrap()[0];
        assert_eq!(tool.name.as_deref(), Some("bash"));
        assert_eq!(tool.description.as_deref(), Some("Custom runner"));
        assert_eq!(tool.input_schema, Some(schema));
    }

    #[test]
    fn test_unknown_tool_passes_through_unchanged() {
        use super::config::{AliasRule, InjectRule, ToolLayerConfig};
        use super::ToolLayer;

        let config = ToolLayerConfig {
            enabled: true,
            capabilities: Default::default(),
            inject: vec![InjectRule {
                tool: "web_search".to_string(),
                if_absent: true,
            }],
            aliases: vec![AliasRule {
                from: "execute_command".to_string(),
                to: "bash".to_string(),
            }],
        };
        let layer = ToolLayer::new(config);
        let mut req = make_request(&["my_custom_tool"]);

        layer.process(&mut req, "anthropic", "claude-sonnet-4-6");

        let names: Vec<_> = req
            .tools
            .as_ref()
            .unwrap()
            .iter()
            .filter_map(|t| t.name.as_deref())
            .collect();
        // Custom tool untouched, web_search injected.
        assert!(names.contains(&"my_custom_tool"));
        assert!(names.contains(&"web_search"));
    }
}

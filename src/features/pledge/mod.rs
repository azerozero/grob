//! Pledge filter: structurally removes tools from the LLM payload before dispatch.
//!
//! Unlike a blacklist (which blocks at execution and causes retries), Pledge
//! strips tool definitions from `CanonicalRequest.tools` so the LLM never
//! sees them. A pledged `read_only` session cannot call `bash` because the
//! tool literally does not exist in the request sent to the provider.

pub mod cli;
pub mod config;
pub mod profiles;

use crate::models::CanonicalRequest;
use config::{PledgeConfig, ResolvedProfile};

/// Applies pledge-based tool filtering to a canonical request.
pub struct PledgeFilter<'a> {
    config: &'a PledgeConfig,
}

impl<'a> PledgeFilter<'a> {
    /// Creates a new filter from the given configuration.
    pub fn new(config: &'a PledgeConfig) -> Self {
        Self { config }
    }

    /// Strips tools that fall outside the active pledge profile.
    ///
    /// The profile is resolved from rules (source / token_prefix match) or
    /// falls back to `config.default_profile`. When `config.enabled` is false
    /// this is a no-op with zero overhead.
    pub fn apply(&self, request: &mut CanonicalRequest, source: Option<&str>, token: Option<&str>) {
        if !self.config.enabled {
            return;
        }

        let profile = self.resolve_profile(source, token);

        if profile.allow_all {
            return;
        }

        Self::filter_tools(request, &profile);
    }

    /// Evaluates rules top-to-bottom, returning the first matching profile.
    fn resolve_profile(&self, source: Option<&str>, token: Option<&str>) -> ResolvedProfile {
        for rule in &self.config.rules {
            if let Some(ref rule_source) = rule.source {
                if source == Some(rule_source.as_str()) {
                    return profiles::resolve(self.config, &rule.profile);
                }
            }
            if let Some(ref prefix) = rule.token_prefix {
                if let Some(tok) = token {
                    if tok.starts_with(prefix.as_str()) {
                        return profiles::resolve(self.config, &rule.profile);
                    }
                }
            }
        }
        profiles::resolve(self.config, &self.config.default_profile)
    }

    /// Retains tools whose name is in the exact allowlist OR matches a pattern.
    fn filter_tools(request: &mut CanonicalRequest, profile: &ResolvedProfile) {
        if let Some(ref mut tools) = request.tools {
            tools.retain(|tool| {
                tool.name.as_deref().is_some_and(|name| {
                    profile.allowed_tools.iter().any(|t| t == name)
                        || profile.allowed_patterns.iter().any(|g| g.is_match(name))
                })
            });
            // NOTE: Empty tools vec is semantically different from None (no
            // tool-use capability at all). We keep the empty vec so the LLM
            // knows tool_use mode is active but has zero tools available.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Tool;
    use config::{PledgeConfig, PledgeProfileConfig, PledgeRule};

    fn make_tool(name: &str) -> Tool {
        Tool {
            r#type: Some("function".to_string()),
            name: Some(name.to_string()),
            description: Some(format!("The {} tool", name)),
            input_schema: None,
        }
    }

    fn make_request(tool_names: &[&str]) -> CanonicalRequest {
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
            tools: Some(tool_names.iter().map(|n| make_tool(n)).collect()),
            tool_choice: None,
            extensions: Default::default(),
        }
    }

    fn tool_names(request: &CanonicalRequest) -> Vec<String> {
        request
            .tools
            .as_ref()
            .map(|tools| tools.iter().filter_map(|t| t.name.clone()).collect())
            .unwrap_or_default()
    }

    #[test]
    fn test_pledge_removes_bash_from_payload() {
        let config = PledgeConfig {
            enabled: true,
            default_profile: "read_only".to_string(),
            profiles: Vec::new(),
            rules: vec![],
        };
        let filter = PledgeFilter::new(&config);
        let mut req = make_request(&["bash", "read_file", "grep", "write_file"]);

        filter.apply(&mut req, None, None);

        let names = tool_names(&req);
        assert!(!names.contains(&"bash".to_string()));
        assert!(names.contains(&"read_file".to_string()));
        assert!(names.contains(&"grep".to_string()));
        assert!(!names.contains(&"write_file".to_string()));
    }

    #[test]
    fn test_pledge_read_only_allows_grep() {
        let config = PledgeConfig {
            enabled: true,
            default_profile: "read_only".to_string(),
            profiles: Vec::new(),
            rules: vec![],
        };
        let filter = PledgeFilter::new(&config);
        let mut req = make_request(&["grep", "list_dir", "web_search"]);

        filter.apply(&mut req, None, None);

        assert_eq!(tool_names(&req), vec!["grep", "list_dir", "web_search"]);
    }

    #[test]
    fn test_pledge_full_allows_all() {
        let config = PledgeConfig {
            enabled: true,
            default_profile: "full".to_string(),
            profiles: Vec::new(),
            rules: vec![],
        };
        let filter = PledgeFilter::new(&config);
        let mut req = make_request(&["bash", "read_file", "write_file", "grep", "nuclear_launch"]);
        let original_count = req.tools.as_ref().unwrap().len();

        filter.apply(&mut req, None, None);

        assert_eq!(req.tools.as_ref().unwrap().len(), original_count);
    }

    #[test]
    fn test_pledge_none_blocks_everything() {
        let config = PledgeConfig {
            enabled: true,
            default_profile: "none".to_string(),
            profiles: Vec::new(),
            rules: vec![],
        };
        let filter = PledgeFilter::new(&config);
        let mut req = make_request(&["bash", "read_file", "grep"]);

        filter.apply(&mut req, None, None);

        assert!(req.tools.as_ref().unwrap().is_empty());
    }

    #[test]
    fn test_pledge_mcp_source_defaults_to_read_only() {
        let config = PledgeConfig {
            enabled: true,
            default_profile: "full".to_string(),
            profiles: Vec::new(),
            rules: vec![PledgeRule {
                source: Some("mcp".to_string()),
                token_prefix: None,
                profile: "read_only".to_string(),
            }],
        };
        let filter = PledgeFilter::new(&config);
        let mut req = make_request(&["bash", "read_file", "grep", "list_dir"]);

        filter.apply(&mut req, Some("mcp"), None);

        let names = tool_names(&req);
        assert!(!names.contains(&"bash".to_string()));
        assert!(names.contains(&"read_file".to_string()));
        assert!(names.contains(&"grep".to_string()));
        assert!(names.contains(&"list_dir".to_string()));
    }

    #[test]
    fn test_pledge_clear_restores_default() {
        // "clear" = no rule match, so default_profile applies
        let config = PledgeConfig {
            enabled: true,
            default_profile: "full".to_string(),
            profiles: Vec::new(),
            rules: vec![PledgeRule {
                source: Some("mcp".to_string()),
                token_prefix: None,
                profile: "read_only".to_string(),
            }],
        };
        let filter = PledgeFilter::new(&config);
        let mut req = make_request(&["bash", "read_file", "grep"]);

        // CLI source doesn't match the mcp rule → falls back to "full"
        filter.apply(&mut req, Some("cli"), None);

        assert_eq!(tool_names(&req).len(), 3);
    }

    #[test]
    fn test_pledge_disabled_is_noop() {
        let config = PledgeConfig {
            enabled: false,
            default_profile: "none".to_string(),
            profiles: Vec::new(),
            rules: vec![],
        };
        let filter = PledgeFilter::new(&config);
        let mut req = make_request(&["bash", "read_file", "grep"]);

        filter.apply(&mut req, None, None);

        // Even though default is "none", disabled means no filtering
        assert_eq!(tool_names(&req).len(), 3);
    }

    #[test]
    fn test_pledge_token_prefix_matching() {
        let config = PledgeConfig {
            enabled: true,
            default_profile: "full".to_string(),
            profiles: Vec::new(),
            rules: vec![PledgeRule {
                source: None,
                token_prefix: Some("grob_ci_".to_string()),
                profile: "read_only".to_string(),
            }],
        };
        let filter = PledgeFilter::new(&config);
        let mut req = make_request(&["bash", "read_file", "grep"]);

        filter.apply(&mut req, None, Some("grob_ci_deploy_token_abc123"));

        let names = tool_names(&req);
        assert!(!names.contains(&"bash".to_string()));
        assert!(names.contains(&"read_file".to_string()));
    }

    // ── SLICE 6: configurable profiles + fail-closed ──

    // A config-defined `[[pledge.profiles]]` profile strips by its own allowlist.
    #[test]
    fn test_pledge_custom_config_profile_strips_by_name() {
        let config = PledgeConfig {
            enabled: true,
            default_profile: "my_custom".to_string(),
            profiles: vec![PledgeProfileConfig {
                name: "my_custom".to_string(),
                allow_all: false,
                allowed_tools: vec!["read_file".to_string(), "my_special_tool".to_string()],
                allowed_tool_patterns: Vec::new(),
            }],
            rules: vec![],
        };
        let filter = PledgeFilter::new(&config);
        let mut req = make_request(&["bash", "read_file", "my_special_tool", "write_file"]);

        filter.apply(&mut req, None, None);

        assert_eq!(tool_names(&req), vec!["read_file", "my_special_tool"]);
    }

    // CRITICAL (the bug this slice fixes): an UNKNOWN profile name must fail
    // CLOSED to `none` (strip everything) — never fall open to `full`.
    #[test]
    fn test_pledge_unknown_profile_fails_closed_to_none() {
        let config = PledgeConfig {
            enabled: true,
            default_profile: "typo_profile_that_does_not_exist".to_string(),
            profiles: vec![],
            rules: vec![],
        };
        let filter = PledgeFilter::new(&config);
        let mut req = make_request(&["bash", "read_file", "grep"]);

        filter.apply(&mut req, None, None);

        assert!(
            req.tools.as_ref().unwrap().is_empty(),
            "unknown profile MUST fail closed to none (strip all), never full"
        );
    }

    // A config profile may override a built-in name (resolution checks config first).
    #[test]
    fn test_pledge_config_profile_overrides_builtin() {
        let config = PledgeConfig {
            enabled: true,
            // Override the built-in `read_only` to additionally allow `bash`.
            default_profile: "read_only".to_string(),
            profiles: vec![PledgeProfileConfig {
                name: "read_only".to_string(),
                allow_all: false,
                allowed_tools: vec!["read_file".to_string(), "bash".to_string()],
                allowed_tool_patterns: Vec::new(),
            }],
            rules: vec![],
        };
        let filter = PledgeFilter::new(&config);
        let mut req = make_request(&["bash", "read_file", "grep"]);

        filter.apply(&mut req, None, None);

        let names = tool_names(&req);
        assert!(names.contains(&"bash".to_string()), "override grants bash");
        assert!(names.contains(&"read_file".to_string()));
        assert!(
            !names.contains(&"grep".to_string()),
            "grep not in the override"
        );
    }

    // FAIL-CLOSED at config load: an unknown profile reference is rejected.
    #[test]
    fn test_config_rejects_unknown_pledge_profile_at_load() {
        let toml = r#"
[router]
default = "alpha"

[[providers]]
name = "p"
provider_type = "openai"
auth_type = "apikey"
api_key = "sk-test"
base_url = "http://127.0.0.1:1"
models = ["alpha"]

[[models]]
name = "alpha"
[[models.mappings]]
priority = 1
provider = "p"
actual_model = "alpha"

[pledge]
enabled = true
default_profile = "does_not_exist"
"#;
        let err = crate::config::AppConfig::from_content(toml, "pledge_unknown_test")
            .expect_err("unknown pledge profile must be rejected at load");
        assert!(
            err.to_string().contains("does_not_exist"),
            "load error must name the offending profile; got: {err}"
        );
    }

    // A custom profile keeps tools by GLOB pattern, in addition to exact names.
    #[test]
    fn test_pledge_profile_pattern_allowlist() {
        let config = PledgeConfig {
            enabled: true,
            default_profile: "patterned".to_string(),
            profiles: vec![PledgeProfileConfig {
                name: "patterned".to_string(),
                allow_all: false,
                allowed_tools: vec!["read_file".to_string()],
                allowed_tool_patterns: vec!["mcp_*".to_string(), "*_read".to_string()],
            }],
            rules: vec![],
        };
        let filter = PledgeFilter::new(&config);
        let mut req = make_request(&["mcp_search", "db_read", "read_file", "bash", "write_file"]);

        filter.apply(&mut req, None, None);

        let names = tool_names(&req);
        assert!(names.contains(&"mcp_search".to_string()), "matches `mcp_*`");
        assert!(names.contains(&"db_read".to_string()), "matches `*_read`");
        assert!(names.contains(&"read_file".to_string()), "exact name kept");
        assert!(
            !names.contains(&"bash".to_string()),
            "no pattern/name match"
        );
        assert!(!names.contains(&"write_file".to_string()));
    }

    // FAIL-CLOSED at load: an invalid glob pattern is a startup error.
    #[test]
    fn test_config_rejects_invalid_pledge_pattern_at_load() {
        let toml = r#"
[router]
default = "alpha"

[[providers]]
name = "p"
provider_type = "openai"
auth_type = "apikey"
api_key = "sk-test"
base_url = "http://127.0.0.1:1"
models = ["alpha"]

[[models]]
name = "alpha"
[[models.mappings]]
priority = 1
provider = "p"
actual_model = "alpha"

[pledge]
enabled = true
default_profile = "broken"
[[pledge.profiles]]
name = "broken"
allowed_tool_patterns = ["mcp_[unclosed"]
"#;
        let err = crate::config::AppConfig::from_content(toml, "pledge_bad_pattern_test")
            .expect_err("invalid pledge tool pattern must be rejected at load");
        assert!(
            err.to_string().contains("invalid tool pattern"),
            "load error must flag the invalid pattern; got: {err}"
        );
    }
}

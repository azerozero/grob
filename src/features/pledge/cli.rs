//! CLI command logic for pledge profile management.
//!
//! Provides `set`, `clear`, `status`, and `list_profiles` subcommands
//! that read local config or delegate to the RPC control plane when the
//! server is running.

use super::config::PledgeConfig;
use super::profiles;

/// Prints all available built-in pledge profiles.
pub fn cmd_list_profiles() {
    let builtins = [
        &profiles::READ_ONLY,
        &profiles::EXECUTE,
        &profiles::FULL,
        &profiles::NONE,
    ];

    println!("  Available pledge profiles:\n");
    for p in &builtins {
        let tools_desc = if p.allow_all {
            "all tools (no restriction)".to_string()
        } else if p.allowed_tools.is_empty() {
            "no tools".to_string()
        } else {
            p.allowed_tools.join(", ")
        };
        println!("    {:12} {}", p.name, tools_desc);
    }
}

/// Prints current pledge configuration status.
pub fn cmd_status(config: &PledgeConfig) {
    if !config.enabled {
        println!("  Pledge:  disabled (all tools pass through)");
        return;
    }

    println!("  Pledge:  enabled");
    println!("  Default: {}", config.default_profile);

    if config.rules.is_empty() {
        println!("  Rules:   none (default profile applies to all requests)");
    } else {
        println!("  Rules:");
        for (i, rule) in config.rules.iter().enumerate() {
            let matcher = match (&rule.source, &rule.token_prefix) {
                (Some(s), _) => format!("source={s}"),
                (_, Some(p)) => format!("token_prefix={p}"),
                _ => "always".to_string(),
            };
            println!("    {}. {} → {}", i + 1, matcher, rule.profile);
        }
    }
}

/// Validates that a profile name corresponds to a known built-in profile.
pub fn validate_profile(name: &str) -> Result<(), String> {
    let known = ["read_only", "execute", "full", "none"];
    if known.contains(&name) {
        Ok(())
    } else {
        Err(format!(
            "unknown profile '{}'. Available: {}",
            name,
            known.join(", ")
        ))
    }
}

/// Formats a pledge set confirmation message.
pub fn format_set_message(profile: &str, source: Option<&str>) -> String {
    match source {
        Some(s) => format!("Pledge profile '{profile}' activated for source '{s}'"),
        None => format!("Pledge profile '{profile}' activated (global)"),
    }
}

/// Formats a pledge clear confirmation message.
pub fn format_clear_message() -> String {
    "Pledge cleared — default profile restored".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::pledge::config::{PledgeConfig, PledgeRule};

    #[test]
    fn validate_known_profiles() {
        assert!(validate_profile("read_only").is_ok());
        assert!(validate_profile("execute").is_ok());
        assert!(validate_profile("full").is_ok());
        assert!(validate_profile("none").is_ok());
    }

    #[test]
    fn validate_unknown_profile() {
        let err = validate_profile("bogus").unwrap_err();
        assert!(err.contains("unknown profile"));
        assert!(err.contains("bogus"));
    }

    #[test]
    fn format_set_global() {
        let msg = format_set_message("read_only", None);
        assert!(msg.contains("read_only"));
        assert!(msg.contains("global"));
    }

    #[test]
    fn format_set_with_source() {
        let msg = format_set_message("execute", Some("mcp"));
        assert!(msg.contains("execute"));
        assert!(msg.contains("mcp"));
    }

    #[test]
    fn format_clear() {
        let msg = format_clear_message();
        assert!(msg.contains("cleared"));
        assert!(msg.contains("default"));
    }

    #[test]
    fn status_disabled_config() {
        let config = PledgeConfig::default();
        assert!(!config.enabled);
    }

    #[test]
    fn status_enabled_with_rules() {
        let config = PledgeConfig {
            enabled: true,
            default_profile: "full".to_string(),
            rules: vec![PledgeRule {
                source: Some("mcp".to_string()),
                token_prefix: None,
                profile: "read_only".to_string(),
            }],
        };
        assert!(config.enabled);
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].profile, "read_only");
    }
}

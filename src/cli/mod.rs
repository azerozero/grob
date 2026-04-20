//! CLI configuration, argument parsing, and validation.

/// CLI argument parsing and subcommand definitions.
pub mod args;
mod config;
mod newtypes;

pub use crate::features::log_export::LogExportConfig;
pub use crate::features::tool_layer::config::ToolLayerConfig;
pub use config::parse_duration;
#[cfg(feature = "harness")]
pub use config::HarnessConfig;
pub use config::{
    AcmeConfig, AuthType, BudgetConfig, CacheConfig, CircuitBreakerProviderConfig,
    ComplianceConfig, EnforcementMode, FanOutConfig, FanOutMode, FipsConfig,
    HealthCheckProviderConfig, ModelConfig, ModelMapping, ModelStrategy, OtelConfig, PoolConfig,
    PoolStrategy, PresetConfig, ProjectConfig, ProjectRouterOverlay, PromptRule, ProviderConfig,
    RouterConfig, SecurityConfig, ServerConfig, TeeConfig, TierConfig, TierMatchCondition,
    TimeoutConfig, TlsConfig, TracingConfig, UserConfig,
};
pub use newtypes::{BodySizeLimit, BudgetUsd, ConfigSource, Port};

// Re-export AppConfig and related helpers from models::config for backwards
// compatibility. Canonical path is `crate::models::config::AppConfig` — this
// re-export keeps existing `crate::cli::AppConfig` call sites working while
// breaking the dependency edge that previously made `cli` part of the mega-SCC.
pub use crate::models::config::{find_project_config, merge_project_config, AppConfig};

/// Format a bind address with proper IPv6 bracket notation.
/// IPv6 hosts (containing `:`) are wrapped in brackets: `[::1]:13456`
/// IPv4 hosts are left as-is: `127.0.0.1:13456`
pub fn format_bind_addr(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    }
}

/// Format a base URL with proper IPv6 bracket notation.
/// IPv6 hosts: `http://[::1]:13456`
/// IPv4 hosts: `http://127.0.0.1:13456`
pub fn format_base_url(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("http://[{}]:{}", host, port)
    } else {
        format!("http://{}:{}", host, port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bind_addr_ipv6() {
        assert_eq!(format_bind_addr("::1", 13456), "[::1]:13456");
    }

    #[test]
    fn test_format_bind_addr_ipv4() {
        assert_eq!(format_bind_addr("127.0.0.1", 13456), "127.0.0.1:13456");
    }

    #[test]
    fn test_format_base_url_ipv6() {
        assert_eq!(format_base_url("::", 13456), "http://[::]:13456");
    }

    #[test]
    fn test_format_base_url_ipv4() {
        assert_eq!(
            format_base_url("127.0.0.1", 13456),
            "http://127.0.0.1:13456"
        );
    }
}

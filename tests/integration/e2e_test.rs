// E2E mock tests
// Tests for full request lifecycle with mockito

use grob::cli::{AppConfig, SecurityTomlConfig};

#[test]
fn test_security_config_defaults() {
    let config = SecurityTomlConfig::default();
    assert!(config.enabled);
    assert_eq!(config.rate_limit_rps, 100);
    assert_eq!(config.rate_limit_burst, 200);
    assert_eq!(config.max_body_size, 10 * 1024 * 1024);
    assert!(config.security_headers);
    assert!(config.circuit_breaker);
    assert!(config.audit_dir.is_empty());
}

#[test]
fn test_security_config_from_toml() {
    let toml_str = r#"
        [router]
        default = "test-model"

        [security]
        enabled = true
        rate_limit_rps = 50
        rate_limit_burst = 100
        max_body_size = 5242880
        security_headers = true
        circuit_breaker = false
        audit_dir = "/tmp/grob-audit"
    "#;

    let config: AppConfig = toml::from_str(toml_str).unwrap();
    assert!(config.security.enabled);
    assert_eq!(config.security.rate_limit_rps, 50);
    assert_eq!(config.security.rate_limit_burst, 100);
    assert_eq!(config.security.max_body_size, 5_242_880);
    assert!(!config.security.circuit_breaker);
    assert_eq!(config.security.audit_dir, "/tmp/grob-audit");
}

#[test]
fn test_security_config_disabled() {
    let toml_str = r#"
        [router]
        default = "test-model"

        [security]
        enabled = false
    "#;

    let config: AppConfig = toml::from_str(toml_str).unwrap();
    assert!(!config.security.enabled);
    // Defaults should still be present
    assert_eq!(config.security.rate_limit_rps, 100);
}

#[test]
fn test_config_version_field() {
    let toml_str = r#"
        version = "1.0"

        [router]
        default = "test-model"
    "#;

    let config: AppConfig = toml::from_str(toml_str).unwrap();
    assert_eq!(config.version.as_deref(), Some("1.0"));
}

#[test]
fn test_model_deprecated_field() {
    let toml_str = r#"
        [router]
        default = "old-model"

        [[models]]
        name = "old-model"
        deprecated = "Use new-model instead"

        [[models.mappings]]
        provider = "test"
        actual_model = "gpt-3.5"
        priority = 1
    "#;

    // Need providers for validation to pass, so parse directly
    let config: AppConfig = toml::from_str(toml_str).unwrap();
    let model = &config.models[0];
    assert_eq!(model.deprecated.as_deref(), Some("Use new-model instead"));
}

#[test]
fn test_config_without_security_section_uses_defaults() {
    let toml_str = r#"
        [router]
        default = "test-model"
    "#;

    let config: AppConfig = toml::from_str(toml_str).unwrap();
    // Should use defaults when [security] section is omitted
    assert!(config.security.enabled);
    assert_eq!(config.security.rate_limit_rps, 100);
    assert_eq!(config.security.rate_limit_burst, 200);
}

// Fan-out unit tests
// Tests for the fan-out (multi-provider parallel request) mode

use grob::cli::{FanOutConfig, FanOutMode, ModelStrategy};

#[test]
fn test_fan_out_mode_defaults_to_fastest() {
    let mode = FanOutMode::default();
    assert_eq!(mode, FanOutMode::Fastest);
}

#[test]
fn test_model_strategy_defaults_to_fallback() {
    let strategy = ModelStrategy::default();
    assert_eq!(strategy, ModelStrategy::Fallback);
}

#[test]
fn test_model_strategy_labels() {
    assert_eq!(ModelStrategy::Fallback.label(), "fallback");
    assert_eq!(ModelStrategy::FanOut.label(), "fan_out");
}

#[test]
fn test_fan_out_config_deserialization() {
    let toml_str = r#"
        mode = "fastest"
    "#;
    let config: FanOutConfig = toml::from_str(toml_str).unwrap();
    assert_eq!(config.mode, FanOutMode::Fastest);
    assert!(config.judge_model.is_none());
    assert!(config.count.is_none());
}

#[test]
fn test_fan_out_config_with_judge() {
    let toml_str = r#"
        mode = "best_quality"
        judge_model = "claude-opus"
        judge_criteria = "Pick the most accurate response"
        count = 3
    "#;
    let config: FanOutConfig = toml::from_str(toml_str).unwrap();
    assert_eq!(config.mode, FanOutMode::BestQuality);
    assert_eq!(config.judge_model.as_deref(), Some("claude-opus"));
    assert_eq!(config.count, Some(3));
}

#[test]
fn test_fan_out_config_count_limit() {
    let config = FanOutConfig {
        mode: FanOutMode::Fastest,
        judge_model: None,
        judge_criteria: None,
        count: Some(2),
    };
    assert_eq!(config.count, Some(2));
}

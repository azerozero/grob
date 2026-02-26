//! Integration tests for the HTTP server and DLP pipeline
//!
//! These tests exercise the full DLP engine pipeline end-to-end,
//! routing decisions, and configuration parsing without needing
//! a live network server.

#[cfg(test)]
mod tests {
    use grob::cli::{AppConfig, RouterConfig, ServerConfig};
    use grob::features::dlp::builtins::builtin_rules;
    use grob::features::dlp::config::*;
    use grob::features::dlp::pii::{PiiScanner, PiiType};
    use grob::features::dlp::session::DlpSessionManager;
    use grob::features::dlp::DlpEngine;
    use grob::models::*;
    use grob::router::Router;

    // ── DLP Engine End-to-End ────────────────────────────────

    fn dlp_config_with_builtins() -> DlpConfig {
        DlpConfig {
            enabled: true,
            scan_input: true,
            scan_output: true,
            ..Default::default()
        }
    }

    #[test]
    fn test_full_dlp_pipeline_secrets() {
        let engine = DlpEngine::from_config(dlp_config_with_builtins()).unwrap();

        // Test multiple secret types in a single text
        let text = concat!(
            "Here are my credentials:\n",
            "OpenAI: sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCD\n",
            "AWS: AKIAIOSFODNN7EXAMPLE\n",
            "GitHub: ghp_abcdefghijklmnopqrstuvwxyz1234567890\n",
        );

        let result = engine.sanitize_text(text);
        assert!(
            !result.contains("sk-proj-"),
            "OpenAI key should be redacted"
        );
        assert!(
            !result.contains("AKIAIOSFODNN7EXAMPLE"),
            "AWS key should be redacted"
        );
        assert!(
            !result.contains("ghp_abcdefghijklmnopqrstuvwxyz1234567890"),
            "GitHub PAT should be redacted"
        );
        // Should contain [REDACTED] markers (builtins use Redact action)
        let redacted_count = result.matches("[REDACTED]").count();
        assert!(
            redacted_count >= 3,
            "Expected >= 3 [REDACTED] markers, got {}",
            redacted_count
        );
    }

    #[test]
    fn test_full_dlp_pipeline_pii() {
        let config = DlpConfig {
            enabled: true,
            pii: PiiConfig {
                credit_cards: true,
                iban: true,
                bic: true,
                action: PiiAction::Redact,
            },
            ..Default::default()
        };
        let engine = DlpEngine::from_config(config).unwrap();

        let text = "Pay to FR7630006000011234567890189 with card 4532015112830366";
        let result = engine.sanitize_text(text);

        assert!(
            result.contains("[IBAN REDACTED]"),
            "IBAN should be redacted, got: {}",
            result
        );
        assert!(
            result.contains("[CARD REDACTED]"),
            "Card should be redacted, got: {}",
            result
        );
        assert!(!result.contains("FR7630006000011234567890189"));
        assert!(!result.contains("4532015112830366"));
    }

    #[test]
    fn test_full_dlp_pipeline_names_and_secrets() {
        let config = DlpConfig {
            enabled: true,
            no_builtins: true,
            secrets: vec![SecretRule {
                name: "test_token".into(),
                prefix: "tok_".into(),
                pattern: "tok_[a-zA-Z0-9]{20}".into(),
                action: SecretAction::Canary,
            }],
            names: vec![NameRule {
                term: "Acme Corp".into(),
                action: NameAction::Pseudonym,
            }],
            ..Default::default()
        };
        let engine = DlpEngine::from_config(config).unwrap();

        // Sanitize input
        let text = "Acme Corp token: tok_abcdefghijklmnopqrst";
        let sanitized = engine.sanitize_text(text);
        assert!(
            !sanitized.contains("Acme Corp"),
            "Name should be anonymized"
        );
        assert!(
            !sanitized.contains("tok_abcdefghijklmnopqrst"),
            "Token should be canary-replaced"
        );

        // Deanonymize response
        let response_text = sanitized.to_string();
        let restored = engine.sanitize_response_text(&response_text);
        assert!(
            restored.contains("Acme Corp"),
            "Name should be restored in response"
        );
    }

    #[test]
    fn test_dlp_request_sanitization() {
        let config = DlpConfig {
            enabled: true,
            no_builtins: true,
            secrets: vec![SecretRule {
                name: "api_key".into(),
                prefix: "sk-test-".into(),
                pattern: "sk-test-[a-zA-Z0-9]{20}".into(),
                action: SecretAction::Redact,
            }],
            ..Default::default()
        };
        let engine = DlpEngine::from_config(config).unwrap();

        let mut request = AnthropicRequest {
            model: "claude-opus-4".to_string(),
            messages: vec![Message {
                role: "user".to_string(),
                content: MessageContent::Text("My key is sk-test-abcdefghijklmnopqrst".to_string()),
            }],
            max_tokens: 1024,
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
        };

        engine.sanitize_request(&mut request);

        match &request.messages[0].content {
            MessageContent::Text(text) => {
                assert!(
                    text.contains("[REDACTED]"),
                    "Secret in message should be redacted, got: {}",
                    text
                );
                assert!(!text.contains("sk-test-abcdefghijklmnopqrst"));
            }
            _ => panic!("Expected text content"),
        }
    }

    #[test]
    fn test_dlp_system_prompt_sanitization() {
        let config = DlpConfig {
            enabled: true,
            names: vec![NameRule {
                term: "InternalProject".into(),
                action: NameAction::Pseudonym,
            }],
            ..Default::default()
        };
        let engine = DlpEngine::from_config(config).unwrap();

        let mut request = AnthropicRequest {
            model: "claude-opus-4".to_string(),
            messages: vec![Message {
                role: "user".to_string(),
                content: MessageContent::Text("Hello".to_string()),
            }],
            max_tokens: 1024,
            thinking: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop_sequences: None,
            stream: None,
            metadata: None,
            system: Some(SystemPrompt::Text(
                "You work on InternalProject".to_string(),
            )),
            tools: None,
            tool_choice: None,
        };

        engine.sanitize_request(&mut request);

        if let Some(SystemPrompt::Text(sys)) = &request.system {
            assert!(
                !sys.contains("InternalProject"),
                "Name in system prompt should be anonymized"
            );
        } else {
            panic!("Expected system prompt");
        }
    }

    // ── Session Isolation ────────────────────────────────────

    #[test]
    fn test_session_isolation_end_to_end() {
        let config = DlpConfig {
            enabled: true,
            no_builtins: true,
            names: vec![NameRule {
                term: "SecretProject".into(),
                action: NameAction::Pseudonym,
            }],
            enable_sessions: true,
            ..Default::default()
        };
        let mgr = DlpSessionManager::from_config(config).unwrap();

        // Two different API keys get different pseudonyms
        let engine_a = mgr.engine_for(Some("key-alice"));
        let engine_b = mgr.engine_for(Some("key-bob"));

        let text_a = engine_a.sanitize_text("Working on SecretProject");
        let text_b = engine_b.sanitize_text("Working on SecretProject");

        assert!(!text_a.contains("SecretProject"));
        assert!(!text_b.contains("SecretProject"));
        assert_ne!(
            text_a.as_ref(),
            text_b.as_ref(),
            "Different sessions should produce different pseudonyms"
        );

        // Each session can deanonymize its own output
        let restored_a = engine_a.sanitize_response_text(&text_a);
        let restored_b = engine_b.sanitize_response_text(&text_b);
        assert!(restored_a.contains("SecretProject"));
        assert!(restored_b.contains("SecretProject"));
    }

    // ── Builtin Rules Coverage ───────────────────────────────

    #[test]
    fn test_builtin_coverage_all_families() {
        let engine = DlpEngine::from_config(dlp_config_with_builtins()).unwrap();

        let test_cases = vec![
            ("OpenAI", "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCD"),
            ("AWS", "AKIAIOSFODNN7EXAMPLE"),
            ("GitHub PAT", "ghp_abcdefghijklmnopqrstuvwxyz1234567890"),
            ("Stripe", concat!("sk_te", "st_abcdefghijklmnopqrstuvwx")),
            ("GCP", "AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe"),
            ("GitLab", "glpat-abcdefghijklmnopq_rst"),
            (
                "Postgres",
                "postgres://admin:secret@db.example.com:5432/mydb",
            ),
        ];

        for (name, secret) in test_cases {
            let input = format!("credential: {}", secret);
            let result = engine.sanitize_text(&input);
            assert!(
                result.contains("[REDACTED]"),
                "{} secret should be detected and redacted: input='{}', output='{}'",
                name,
                input,
                result,
            );
        }
    }

    #[test]
    fn test_builtin_no_false_positive_on_normal_text() {
        let engine = DlpEngine::from_config(dlp_config_with_builtins()).unwrap();

        let benign_texts = vec![
            "Hello, how are you today?",
            "The weather is nice in Paris.",
            "fn main() { println!(\"Hello\"); }",
            "SELECT * FROM users WHERE id = 42",
            "https://example.com/api/v1/data",
            "The quick brown fox jumps over the lazy dog",
        ];

        for text in benign_texts {
            let result = engine.sanitize_text(text);
            assert_eq!(
                result.as_ref(),
                text,
                "Benign text should not be modified: '{}'",
                text
            );
        }
    }

    // ── PII Validation ───────────────────────────────────────

    #[test]
    fn test_pii_luhn_rejects_sequential_numbers() {
        let scanner = PiiScanner::from_config(&PiiConfig {
            credit_cards: true,
            iban: false,
            bic: false,
            action: PiiAction::Redact,
        })
        .unwrap();

        // Sequential digits that look like card numbers but fail Luhn
        let false_positives = vec!["1234567890123456", "1111111111111111", "9999999999999999"];

        for fp in false_positives {
            let text = format!("number: {} end", fp);
            let result = scanner.redact(&text);
            if let Some((_, detections)) = result {
                assert!(
                    detections.iter().all(|d| d.pii_type != PiiType::CreditCard),
                    "Luhn should reject sequential number: {}",
                    fp
                );
            }
        }
    }

    #[test]
    fn test_pii_iban_validates_multiple_countries() {
        let scanner = PiiScanner::from_config(&PiiConfig {
            credit_cards: false,
            iban: true,
            bic: false,
            action: PiiAction::Redact,
        })
        .unwrap();

        let valid_ibans = vec![
            ("France", "FR7630006000011234567890189"),
            ("Germany", "DE89370400440532013000"),
            ("UK", "GB29NWBK60161331926819"),
        ];

        for (country, iban) in valid_ibans {
            let text = format!("IBAN: {}", iban);
            let result = scanner.redact(&text);
            assert!(
                result.is_some(),
                "{} IBAN should be detected: {}",
                country,
                iban
            );
            let (redacted, _) = result.unwrap();
            assert!(
                redacted.contains("[IBAN REDACTED]"),
                "{} IBAN should be redacted",
                country
            );
        }
    }

    // ── Routing End-to-End ───────────────────────────────────

    fn test_router() -> Router {
        Router::new(AppConfig {
            server: ServerConfig::default(),
            router: RouterConfig {
                default: "gpt-4o".to_string(),
                background: Some("gpt-4o-mini".to_string()),
                think: Some("claude-opus-4".to_string()),
                websearch: Some("claude-sonnet-search".to_string()),
                auto_map_regex: Some("^claude-".to_string()),
                background_regex: Some("(?i)claude.*haiku".to_string()),
                prompt_rules: vec![],
                gdpr: false,
                region: None,
            },
            providers: vec![],
            models: vec![],
            presets: Default::default(),
            budget: Default::default(),
            dlp: Default::default(),
            auth: Default::default(),
            tap: Default::default(),
            security: Default::default(),
            cache: Default::default(),
            compliance: Default::default(),
            version: None,
            user: Default::default(),
        })
    }

    #[test]
    fn test_routing_think_mode() {
        let router = test_router();
        let mut req = AnthropicRequest {
            model: "claude-opus-4".to_string(),
            messages: vec![Message {
                role: "user".to_string(),
                content: MessageContent::Text("Plan the architecture".to_string()),
            }],
            max_tokens: 16384,
            thinking: Some(ThinkingConfig {
                r#type: "enabled".to_string(),
                budget_tokens: Some(10000),
            }),
            temperature: None,
            top_p: None,
            top_k: None,
            stop_sequences: None,
            stream: None,
            metadata: None,
            system: None,
            tools: None,
            tool_choice: None,
        };
        let decision = router.route(&mut req).unwrap();
        assert_eq!(decision.route_type, RouteType::Think);
        assert_eq!(decision.model_name, "claude-opus-4");
    }

    #[test]
    fn test_routing_websearch_priority_over_think() {
        let router = test_router();
        let mut req = AnthropicRequest {
            model: "claude-sonnet-4".to_string(),
            messages: vec![Message {
                role: "user".to_string(),
                content: MessageContent::Text("Search for Rust news".to_string()),
            }],
            max_tokens: 8192,
            thinking: Some(ThinkingConfig {
                r#type: "enabled".to_string(),
                budget_tokens: Some(5000),
            }),
            temperature: None,
            top_p: None,
            top_k: None,
            stop_sequences: None,
            stream: None,
            metadata: None,
            system: None,
            tools: Some(vec![Tool {
                r#type: Some("web_search_2025_04".to_string()),
                name: Some("web_search".to_string()),
                description: None,
                input_schema: None,
            }]),
            tool_choice: None,
        };
        let decision = router.route(&mut req).unwrap();
        assert_eq!(decision.route_type, RouteType::WebSearch);
    }

    #[test]
    fn test_routing_background_haiku() {
        let router = test_router();
        let mut req = AnthropicRequest {
            model: "claude-3-5-haiku-20241022".to_string(),
            messages: vec![Message {
                role: "user".to_string(),
                content: MessageContent::Text("Quick task".to_string()),
            }],
            max_tokens: 1024,
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
        };
        let decision = router.route(&mut req).unwrap();
        assert_eq!(decision.route_type, RouteType::Background);
        assert_eq!(decision.model_name, "gpt-4o-mini");
    }

    // ── Config Parsing ───────────────────────────────────────

    #[test]
    fn test_dlp_config_full_parse() {
        let toml_str = r#"
enabled = true
scan_input = true
scan_output = false
no_builtins = true
enable_sessions = true

[[secrets]]
name = "custom_key"
prefix = "myapp_"
pattern = "myapp_[a-z]{32}"
action = "redact"

[[names]]
term = "CompanyName"
action = "pseudonym"

[entropy]
enabled = true
action = "log"

[pii]
credit_cards = true
iban = true
bic = true
action = "redact"
        "#;
        let config: DlpConfig = toml::from_str(toml_str).unwrap();
        assert!(config.enabled);
        assert!(config.scan_input);
        assert!(!config.scan_output);
        assert!(config.no_builtins);
        assert!(config.enable_sessions);
        assert_eq!(config.secrets.len(), 1);
        assert_eq!(config.secrets[0].action, SecretAction::Redact);
        assert_eq!(config.names.len(), 1);
        assert!(config.entropy.enabled);
        assert!(config.pii.credit_cards);
        assert!(config.pii.iban);
        assert!(config.pii.bic);
        assert_eq!(config.pii.action, PiiAction::Redact);
    }

    #[test]
    fn test_dlp_config_defaults() {
        let config: DlpConfig = toml::from_str("enabled = true").unwrap();
        assert!(config.scan_input);
        assert!(config.scan_output);
        assert!(!config.no_builtins);
        assert!(!config.enable_sessions);
        assert!(config.pii.credit_cards);
        assert!(config.pii.iban);
        assert!(!config.pii.bic);
    }

    #[test]
    fn test_builtin_rules_no_duplicates() {
        let rules = builtin_rules();
        let mut names: Vec<&str> = rules.iter().map(|r| r.name.as_str()).collect();
        names.sort();
        let original_len = names.len();
        names.dedup();
        assert_eq!(
            names.len(),
            original_len,
            "Builtin rules should have unique names"
        );
    }

    #[test]
    fn test_no_builtins_flag_works_in_engine() {
        let config_with = DlpConfig {
            enabled: true,
            no_builtins: false,
            ..Default::default()
        };
        let config_without = DlpConfig {
            enabled: true,
            no_builtins: true,
            ..Default::default()
        };

        let engine_with = DlpEngine::from_config(config_with).unwrap();
        let engine_without = DlpEngine::from_config(config_without).unwrap();

        let text = "key: sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCD";
        let result_with = engine_with.sanitize_text(text);
        let result_without = engine_without.sanitize_text(text);

        assert!(
            result_with.contains("[REDACTED]"),
            "With builtins should detect OpenAI key"
        );
        assert_eq!(
            result_without.as_ref(),
            text,
            "Without builtins should NOT detect OpenAI key"
        );
    }
}

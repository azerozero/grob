use criterion::{black_box, criterion_group, criterion_main, Criterion};
use grob::cli::{AppConfig, RouterConfig, ServerConfig};
use grob::features::dlp::builtins::builtin_rules;
use grob::features::dlp::config::*;
use grob::features::dlp::dfa::SecretScanner;
use grob::features::dlp::pii::PiiScanner;
use grob::features::dlp::DlpEngine;
use grob::models::*;
use grob::router::Router;

// ── Router Benchmarks ────────────────────────────────────────

fn make_router() -> Router {
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
        version: None,
        user: Default::default(),
    })
}

fn make_request(model: &str, text: &str) -> AnthropicRequest {
    AnthropicRequest {
        model: model.to_string(),
        messages: vec![Message {
            role: "user".to_string(),
            content: MessageContent::Text(text.to_string()),
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
    }
}

fn bench_routing(c: &mut Criterion) {
    let router = make_router();

    c.bench_function("route_default", |b| {
        b.iter(|| {
            let mut req = make_request("claude-sonnet-4", "Write a hello world");
            black_box(router.route(&mut req).unwrap())
        });
    });

    c.bench_function("route_background_haiku", |b| {
        b.iter(|| {
            let mut req = make_request("claude-3-5-haiku-20241022", "Quick task");
            black_box(router.route(&mut req).unwrap())
        });
    });

    c.bench_function("route_think_mode", |b| {
        b.iter(|| {
            let mut req = make_request("claude-opus-4", "Plan architecture");
            req.thinking = Some(ThinkingConfig {
                r#type: "enabled".to_string(),
                budget_tokens: Some(10000),
            });
            black_box(router.route(&mut req).unwrap())
        });
    });

    c.bench_function("route_websearch", |b| {
        b.iter(|| {
            let mut req = make_request("claude-sonnet-4", "Search news");
            req.tools = Some(vec![Tool {
                r#type: Some("web_search_2025_04".to_string()),
                name: Some("web_search".to_string()),
                description: None,
                input_schema: None,
            }]);
            black_box(router.route(&mut req).unwrap())
        });
    });
}

// ── DLP Secret Scanner Benchmarks ────────────────────────────

fn bench_dlp_scanner(c: &mut Criterion) {
    let rules = builtin_rules();
    let scanner = SecretScanner::new(&rules, &[]);

    // Benign text (fast path: prefix byte check should reject)
    let benign = "The quick brown fox jumps over the lazy dog. \
                  This is a normal message with no secrets at all. \
                  Just regular English text.";

    c.bench_function("dlp_scan_benign_prefilter", |b| {
        b.iter(|| black_box(scanner.might_contain_secret(benign)))
    });

    // Text with a prefix byte but no actual match (partial fast path)
    let has_prefix = "Please check the GitHub repository for details. \
                      The API gateway handles authentication.";

    c.bench_function("dlp_scan_prefix_hit_no_match", |b| {
        b.iter(|| {
            if scanner.might_contain_secret(has_prefix) {
                black_box(scanner.scan(has_prefix));
            }
        })
    });

    // Text with actual secrets (full scan + match)
    let with_secrets = "Credentials: AKIAIOSFODNN7EXAMPLE and \
                        ghp_abcdefghijklmnopqrstuvwxyz1234567890 \
                        also sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCD";

    c.bench_function("dlp_scan_3_secrets", |b| {
        b.iter(|| black_box(scanner.scan(with_secrets)))
    });

    // Large text (typical LLM response ~4KB)
    let large_text =
        "Normal text. ".repeat(300) + "AKIAIOSFODNN7EXAMPLE" + &" more text.".repeat(50);

    c.bench_function("dlp_scan_4kb_1_secret", |b| {
        b.iter(|| {
            if scanner.might_contain_secret(&large_text) {
                black_box(scanner.scan(&large_text));
            }
        })
    });
}

// ── DLP Engine End-to-End Benchmark ──────────────────────────

fn bench_dlp_engine(c: &mut Criterion) {
    let config = DlpConfig {
        enabled: true,
        names: vec![NameRule {
            term: "Thales".into(),
            action: NameAction::Pseudonym,
        }],
        pii: PiiConfig {
            credit_cards: true,
            iban: true,
            bic: false,
            action: PiiAction::Redact,
        },
        ..Default::default()
    };
    let engine = DlpEngine::from_config(config).unwrap();

    let clean_text = "Hello, please review this code and provide feedback.";

    c.bench_function("dlp_engine_clean_text", |b| {
        b.iter(|| black_box(engine.sanitize_text(clean_text)))
    });

    let mixed_text = "Working at Thales with key AKIAIOSFODNN7EXAMPLE \
                      and card 4532015112830366 also IBAN FR7630006000011234567890189";

    c.bench_function("dlp_engine_mixed_detections", |b| {
        b.iter(|| black_box(engine.sanitize_text(mixed_text)))
    });
}

// ── PII Scanner Benchmarks ───────────────────────────────────

fn bench_pii(c: &mut Criterion) {
    let scanner = PiiScanner::from_config(&PiiConfig {
        credit_cards: true,
        iban: true,
        bic: false,
        action: PiiAction::Redact,
    })
    .unwrap();

    let no_pii = "This is a regular text without any financial data or numbers.";

    c.bench_function("pii_prefilter_reject", |b| {
        b.iter(|| black_box(scanner.might_contain_pii(no_pii)))
    });

    let with_card = "Payment with card 4532015112830366 was processed successfully.";

    c.bench_function("pii_detect_credit_card", |b| {
        b.iter(|| black_box(scanner.redact(with_card)))
    });

    let with_iban = "Transfer to FR7630006000011234567890189 confirmed.";

    c.bench_function("pii_detect_iban", |b| {
        b.iter(|| black_box(scanner.redact(with_iban)))
    });
}

// ── Builtin Rules Compilation ────────────────────────────────

fn bench_builtins(c: &mut Criterion) {
    c.bench_function("builtin_rules_generate", |b| {
        b.iter(|| black_box(builtin_rules()))
    });

    c.bench_function("builtin_scanner_compile", |b| {
        b.iter(|| {
            let rules = builtin_rules();
            black_box(SecretScanner::new(&rules, &[]))
        })
    });
}

criterion_group!(
    benches,
    bench_routing,
    bench_dlp_scanner,
    bench_dlp_engine,
    bench_pii,
    bench_builtins,
);
criterion_main!(benches);

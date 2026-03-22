use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use grob::features::policies::config::{MatchRules, PolicyConfig};
use grob::features::policies::context::RequestContext;
use grob::features::policies::matcher::PolicyMatcher;

// ── Policy bench helpers ─────────────────────────────────────────────────────

fn make_policy_config(n: usize) -> Vec<PolicyConfig> {
    (0..n)
        .map(|i| PolicyConfig {
            name: format!("policy-{i}"),
            match_rules: MatchRules {
                tenant: if i % 3 == 0 {
                    Some(format!("tenant-{i}*"))
                } else {
                    None
                },
                zone: if i % 4 == 0 {
                    Some(format!("zone-{i}"))
                } else {
                    None
                },
                project: None,
                user: None,
                agent: if i % 5 == 0 {
                    Some("claude-code*".to_string())
                } else {
                    None
                },
                compliance: if i % 6 == 0 {
                    Some(vec!["gdpr".to_string()])
                } else {
                    None
                },
                model: None,
                provider: None,
                dlp_triggered: None,
                cost_above: None,
                route_type: None,
            },
            dlp: None,
            rate_limit: None,
            routing: None,
            budget: None,
            log_export: None,
            hit: None,
        })
        .collect()
}

fn make_context() -> RequestContext {
    RequestContext {
        tenant: Some("tenant-3".to_string()),
        zone: Some("zone-4".to_string()),
        project: Some("my-project".to_string()),
        user: Some("alice@company.com".to_string()),
        agent: Some("claude-code/1.0".to_string()),
        compliance: vec!["gdpr".to_string()],
        model: "claude-sonnet-4-6".to_string(),
        provider: "anthropic".to_string(),
        route_type: "default".to_string(),
        dlp_triggered: false,
        estimated_cost: 0.02,
    }
}

// ── Benchmarks ───────────────────────────────────────────────────────────────

fn bench_policy_evaluate(c: &mut Criterion) {
    let mut group = c.benchmark_group("policy_evaluate");

    for n in [5, 10, 20, 50] {
        let configs = make_policy_config(n);
        let matcher = PolicyMatcher::new(configs).expect("valid config");
        let ctx = make_context();

        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| matcher.evaluate(black_box(&ctx)));
        });
    }

    group.finish();
}

criterion_group!(benches, bench_policy_evaluate);
criterion_main!(benches);

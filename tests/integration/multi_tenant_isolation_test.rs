//! Multi-tenant isolation regression tests.
//!
//! These tests assert that tenant boundaries are strictly enforced across
//! the audit log, response cache, budget tracker, secret backends, and
//! request authentication. The audit performed before this file landed
//! found `tenant_id` declared in `src/server/dispatch/mod.rs` and used in
//! audit logging but **zero tests** validating tenant boundaries — a
//! regulatory compliance gap (cross-tenant data leak risk).
//!
//! When a test is marked `#[ignore]`, the codebase does not yet enforce
//! the property under test; the test stands as a regression target for
//! the follow-up fix and points at the relevant gap with a `TODO`.

use grob::auth::jwt::GrobClaims;
use grob::cache::{CachedResponse, ResponseCache};
use grob::cli::SecretsConfig;
use grob::features::token_pricing::spend::SpendTracker;
use grob::models::{CanonicalRequest, Message, MessageContent};
use grob::security::audit_log::{AuditConfig, AuditEntry, AuditEvent, AuditLog, SigningAlgorithm};
use grob::server::AuditEntryBuilder;
use grob::storage::secrets::build_backend;
use grob::storage::GrobStore;
use std::sync::Arc;
use tempfile::TempDir;

// ── Helpers ────────────────────────────────────────────────────────────

/// Builds a minimal audit log writing into `dir` with default ECDSA signing.
fn make_audit_log(dir: &TempDir) -> AuditLog {
    AuditLog::new(AuditConfig {
        log_dir: dir.path().to_path_buf(),
        sign_key_path: None,
        signing_algorithm: SigningAlgorithm::default(),
        hmac_key_path: None,
        batch_size: 1,
        flush_interval_ms: 5000,
        include_merkle_proof: false,
    })
    .expect("audit log construction")
}

/// Reads every audit entry written to the log so a test can grep / filter.
fn read_audit_entries(dir: &TempDir) -> Vec<AuditEntry> {
    let path = dir.path().join("current.jsonl");
    let content = std::fs::read_to_string(&path).expect("read audit log");
    content
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_str::<AuditEntry>(line).expect("parse audit entry"))
        .collect()
}

/// Creates a deterministic request body shared by both tenants for cache tests.
fn shared_request() -> CanonicalRequest {
    CanonicalRequest {
        model: "claude-3-5-sonnet".to_string(),
        messages: vec![Message {
            role: "user".to_string(),
            content: MessageContent::Text("ping".to_string()),
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
        extensions: Default::default(),
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[test]
fn tenant_audit_log_is_filtered() {
    // REGRESSION GUARD: keeps audit-log tenant boundaries enforceable. If
    // `AuditEntryBuilder` ever stops persisting `tenant_id` verbatim, the
    // compliance team loses the only mechanism to filter per-tenant access
    // for HDS / SecNumCloud / EU AI Act audits.
    let dir = TempDir::new().expect("tempdir");
    let log = make_audit_log(&dir);

    // Tenant A makes 3 requests; tenant B makes 2.
    for _ in 0..3 {
        let entry =
            AuditEntryBuilder::new("tenant_a", AuditEvent::Request, "anthropic", "10.0.0.1", 12)
                .build();
        log.write(entry).expect("audit write");
    }
    for _ in 0..2 {
        let entry =
            AuditEntryBuilder::new("tenant_b", AuditEvent::Request, "anthropic", "10.0.0.2", 9)
                .build();
        log.write(entry).expect("audit write");
    }

    let entries = read_audit_entries(&dir);
    assert_eq!(entries.len(), 5, "five total entries written");

    let tenant_a: Vec<_> = entries
        .iter()
        .filter(|e| e.tenant_id == "tenant_a")
        .collect();
    let tenant_b: Vec<_> = entries
        .iter()
        .filter(|e| e.tenant_id == "tenant_b")
        .collect();

    assert_eq!(
        tenant_a.len(),
        3,
        "tenant_a query returns exactly its own 3 entries"
    );
    assert_eq!(
        tenant_b.len(),
        2,
        "tenant_b query returns exactly its own 2 entries"
    );
    assert!(
        tenant_a.iter().all(|e| e.tenant_id == "tenant_a"),
        "tenant_a query never leaks tenant_b records"
    );
    assert!(
        tenant_b.iter().all(|e| e.tenant_id == "tenant_b"),
        "tenant_b query never leaks tenant_a records"
    );
}

#[test]
fn tenant_cache_response_is_not_shared() {
    // REGRESSION GUARD: cache key MUST include tenant_id so two tenants with
    // identical prompts cannot read each other's cached LLM output. This is
    // the only protection against a cross-tenant data leak when
    // `[cache] enabled = true`.
    let cache = ResponseCache::new(100, 60, 1_000_000, 3);
    let req = shared_request();

    let key_a =
        ResponseCache::compute_key_from_request("tenant_a", &req).expect("tenant_a cache key");
    let key_b =
        ResponseCache::compute_key_from_request("tenant_b", &req).expect("tenant_b cache key");

    assert_ne!(
        key_a, key_b,
        "identical request bodies MUST yield different cache keys per tenant"
    );

    // Tenant A populates the cache.
    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    runtime.block_on(async {
        cache
            .put(
                key_a.clone(),
                CachedResponse {
                    body: br#"{"content":"tenant_a-only"}"#.to_vec(),
                    content_type: "application/json".to_string(),
                    provider: "anthropic".to_string(),
                    model: "claude-3-5-sonnet".to_string(),
                },
            )
            .await;

        // Tenant A hits the cache.
        let hit_a = cache.get(&key_a).await;
        assert!(hit_a.is_some(), "tenant_a should hit its own cache entry");

        // Tenant B with the IDENTICAL request body MUST NOT read A's response.
        let miss_b = cache.get(&key_b).await;
        assert!(
            miss_b.is_none(),
            "tenant_b MUST miss when only tenant_a populated the cache"
        );
    });
}

#[test]
fn tenant_spend_storage_is_isolated() {
    // REGRESSION GUARD: per-tenant spend events recorded via
    // `SpendTracker::record_tenant` MUST be tagged with the tenant in the
    // append-only journal so a per-tenant replay can recover only that
    // tenant's costs. Without the tagging, chargeback exports collapse
    // every tenant's totals onto whichever tenant runs the export.
    let dir = TempDir::new().expect("tempdir");
    // GrobStore writes its journal under `<base_dir>/spend/YYYY-MM.jsonl` where
    // `<base_dir>` is the parent of the path passed to `open`.
    let store_root = dir.path().to_path_buf();
    let store = Arc::new(GrobStore::open(&store_root.join("grob.db")).expect("open store"));
    let mut tracker = SpendTracker::with_store(store.clone());

    // Tenant A spends $11; tenant B spends $50.
    tracker.record_tenant("tenant_a", "anthropic", "claude-opus", 11.0);
    tracker.record_tenant("tenant_b", "anthropic", "claude-opus", 50.0);
    tracker.save();

    // Read back the JSONL spend journal: each line is one event, tagged
    // with `tenant` whenever `record_tenant` was used.
    let month = chrono::Utc::now().format("%Y-%m").to_string();
    let journal_path = store_root.join("spend").join(format!("{month}.jsonl"));
    let raw = std::fs::read_to_string(&journal_path).expect("read spend journal");
    let mut a_total = 0.0_f64;
    let mut b_total = 0.0_f64;
    for line in raw.lines().filter(|l| !l.is_empty()) {
        let value: serde_json::Value = serde_json::from_str(line).expect("parse spend event");
        let cost = value["cost_usd"].as_f64().unwrap_or(0.0);
        match value["tenant"].as_str() {
            Some("tenant_a") => a_total += cost,
            Some("tenant_b") => b_total += cost,
            _ => {}
        }
    }

    assert!(
        (a_total - 11.0).abs() < 0.001,
        "tenant_a journal events sum to only A's spend (got {a_total})"
    );
    assert!(
        (b_total - 50.0).abs() < 0.001,
        "tenant_b journal events sum to only B's spend (got {b_total})"
    );
    // Tenant A's spend is not charged to tenant B's quota and vice versa.
    assert!(
        a_total < b_total,
        "isolated tenant accounting cannot collapse two tenants' totals"
    );
}

#[ignore = "TODO: SpendTracker::check_budget does not accept a tenant_id; per-tenant \
            budget enforcement must be added before this test can pass. \
            See audit: cross-tenant budget leak (src/features/token_pricing/spend.rs)"]
#[test]
fn tenant_budget_quota_is_isolated() {
    // REGRESSION GUARD: tenant A with `monthly_limit_usd = 10` exceeding its
    // budget MUST NOT block tenant B (whose own limit = 100). Today
    // `record_tenant` ALSO accumulates into the global counter
    // (spend.rs:139), so a tenant-scoped overspend mistakenly trips the
    // global budget. This test must remain `#[ignore]` until the budget
    // tracker grows a tenant parameter to `check_budget`.
    let dir = TempDir::new().expect("tempdir");
    let store = Arc::new(GrobStore::open(&dir.path().join("grob.db")).expect("open store"));
    let mut tracker = SpendTracker::with_store(store);

    // Tenant A spends $11 (exceeds $10 quota).
    tracker.record_tenant("tenant_a", "anthropic", "claude-opus", 11.0);
    // Tenant B spends $50 (well under $100 quota).
    tracker.record_tenant("tenant_b", "anthropic", "claude-opus", 50.0);

    // Once per-tenant budget exists, the API will look like:
    //   tracker.check_tenant_budget("tenant_a", "...", "...", Some(10.0))
    //     => Err(BudgetExceeded)
    //   tracker.check_tenant_budget("tenant_b", "...", "...", Some(100.0))
    //     => Ok(())
    panic!("tenant-scoped check_budget(...) is not yet implemented");
}

#[ignore = "TODO: SecretBackend has no tenant scope. EnvBackend / FileBackend / \
            LocalEncryptedBackend resolve `secret:groq` globally. Per-tenant \
            credential isolation requires a `get(name, tenant)` overload or a \
            tenant-prefixed key strategy. See audit: cross-tenant credential leak \
            (src/storage/secrets.rs)"]
#[test]
fn tenant_credentials_are_scoped() {
    // REGRESSION GUARD: `secret:groq` for tenant A MUST resolve to A's value
    // (X), and to B's value (Y) when looked up for tenant B. Today
    // `SecretBackend::get(&self, name)` accepts no tenant context, so any
    // tenant can fetch any tenant's API key. This test will start passing
    // when the `SecretBackend` trait grows a tenant parameter.
    let dir = TempDir::new().expect("tempdir");
    let store = Arc::new(GrobStore::open(&dir.path().join("grob.db")).expect("open store"));
    let cfg = SecretsConfig::default();
    let backend = build_backend(&cfg, store);

    // The "tenant_a" call site cannot disambiguate from the "tenant_b" one.
    let _value: Option<_> = backend.get("groq");

    panic!("SecretBackend::get does not accept a tenant_id parameter");
}

#[ignore = "TODO: `[security] strict_tenant` config does not exist. Adding it \
            requires a SecurityConfig field and a guard in auth_middleware that \
            short-circuits a 400 when neither GrobClaims nor VirtualKeyContext \
            is present. See audit: missing strict-tenant enforcement \
            (src/server/middleware.rs, src/cli/config/security.rs)"]
#[test]
fn tenant_id_required_in_strict_mode() {
    // REGRESSION GUARD: when `[security] strict_tenant = true`, requests
    // arriving with neither a JWT `tenant_id` claim nor a virtual-key tenant
    // mapping MUST be rejected with HTTP 400 and a body that names the
    // missing input. Today there is no such config flag, so the server
    // happily logs `tenant_id = "anon"` for every anonymous request.
    panic!("strict_tenant config flag is not yet implemented");
}

#[test]
fn tenant_jwt_claim_is_authoritative() {
    // REGRESSION GUARD: when JWT auth is enabled, the `tenant` claim (with
    // fallback to `sub`) is the source of truth used by the dispatch
    // pipeline. A client-supplied `X-Tenant-ID` header MUST never override
    // it. We pin the JWT-side contract here; if/when an `X-Tenant-ID`
    // header is honoured by middleware, an additional handler-level test
    // must assert the JWT value still wins on mismatch.
    //
    // PR #311 introduced `extract_tenant_id()` in `src/server/handlers.rs`,
    // which prefers the VirtualKeyContext over `GrobClaims`. Both paths
    // ignore any free-form header — we pin the GrobClaims contract here.
    let claims = GrobClaims {
        sub: "user-123".to_string(),
        tenant: Some("tenant_a".to_string()),
        exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as u64,
        iss: None,
        aud: None,
    };
    assert_eq!(
        claims.tenant_id(),
        "tenant_a",
        "explicit `tenant` claim wins over `sub`"
    );

    let claims_sub_only = GrobClaims {
        sub: "tenant_b".to_string(),
        tenant: None,
        exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as u64,
        iss: None,
        aud: None,
    };
    assert_eq!(
        claims_sub_only.tenant_id(),
        "tenant_b",
        "`sub` is used as tenant when no explicit claim is present"
    );

    // Cross-tenant assertion: two distinct claims yield distinct tenant ids.
    assert_ne!(claims.tenant_id(), claims_sub_only.tenant_id());
}

#[ignore = "TODO: ToolSpikeDetector lands in PR #308 (feat/anomaly-detection-tool-spike) \
            and is not yet on this branch. Re-enable once the detector is merged \
            and exposes a per-tenant `record_tool_call` / `is_blocked` API."]
#[test]
fn tenant_anomaly_detector_is_per_tenant() {
    // REGRESSION GUARD: tenant A spiking 600 tool calls/min MUST be blocked
    // independently of tenant B's traffic (50/min). The detector must key
    // on `tenant_id`, not on global counters, otherwise one noisy tenant
    // takes down every other tenant's tool-calling capability.
    panic!("ToolSpikeDetector not yet present on this branch");
}

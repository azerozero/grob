//! Persistent credential read costs, including the durable clock watermark.
//! Run `cargo bench --bench credential_store`; no production data is opened.
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use grob::{
    credentials::{
        config::ServiceBinding,
        record::{Authority, Bundle, CredentialRecord},
    },
    storage::GrobStore,
};
use std::hint::black_box;

fn bench_store(c: &mut Criterion) {
    let dir = tempfile::tempdir().unwrap();
    let store = GrobStore::open(&dir.path().join("grob.db")).unwrap();
    let binding: ServiceBinding = serde_json::from_value(serde_json::json!({
        "id":"bench", "tenant":"bench", "agents":["jwt:bench"], "origin":"https://example.com",
        "allowed_ips":["203.0.113.1"], "paths":["/"], "methods":["GET"], "injection":{"type":"bearer"}
    })).unwrap();
    let record = CredentialRecord::provision(
        &binding,
        Authority::Local,
        Some(Bundle {
            token: "synthetic-benchmark-token".into(),
            username: String::new(),
            password: String::new(),
        }),
        None,
    );
    store.credential_publish(record.clone(), None).unwrap();
    let mut group = c.benchmark_group("credential_store");
    group
        .sample_size(100)
        .warm_up_time(std::time::Duration::from_secs(1))
        .measurement_time(std::time::Duration::from_secs(3));
    group.bench_function("read_current_watermark", |b| {
        b.iter(|| black_box(store.credential_read("bench", "bench").unwrap()))
    });
    group.bench_function("read_advances_watermark", |b| {
        b.iter_batched(
            || {
                let mut stale = record.clone();
                stale.observed_at = chrono::Utc::now().timestamp() - 1;
                store.credential_publish(stale, None).unwrap();
            },
            |()| black_box(store.credential_read("bench", "bench").unwrap()),
            BatchSize::PerIteration,
        )
    });
    group.finish();
}
criterion_group!(benches, bench_store);
criterion_main!(benches);

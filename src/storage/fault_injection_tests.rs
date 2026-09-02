//! Fault-injection tests for the ADR-0030 fail-closed dependency contract.
//!
//! ADR-0030 splits every hot-path dependency in two: *authorizing* ones, whose
//! failure must block the request, and *observing* ones, whose failure must let
//! it through. The budget tests elsewhere cover the **decision** ("spend is over
//! the cap, so deny"). These cover the **dependency-unavailable** variants,
//! which are the ones that regress silently: nothing throws, the counter simply
//! reads as zero, and an exhausted budget quietly reopens.
//!
//! That is exactly how LiteLLM's `fail_closed_budget_enforcement` regressed, so
//! each authorizing failure mode gets a test asserting we refuse rather than
//! serve.

use super::*;
use std::fs;
use tempfile::TempDir;

// ── Helpers ──────────────────────────────────────────────────────

/// Path to the current month's global spend journal inside `dir`.
fn journal_path(dir: &TempDir) -> std::path::PathBuf {
    let month = crate::features::token_pricing::spend::current_month();
    dir.path().join("spend").join(format!("{month}.jsonl"))
}

/// Opens a store rooted at `dir` the way production does.
fn open_store(dir: &TempDir) -> Result<GrobStore> {
    GrobStore::open(&dir.path().join("grob.db"))
}

// ── Authorizing: spend journal ───────────────────────────────────

/// A torn write must stop the process from starting.
///
/// The dangerous alternative is starting with `total = 0`: the recorded spend
/// vanishes and the budget silently reopens.
#[test]
fn corrupt_spend_journal_blocks_startup() {
    let dir = TempDir::new().expect("tempdir");
    {
        let store = open_store(&dir).expect("first open must succeed");
        store.record_spend(None, 42.0, "anthropic", "claude-opus");
        store.flush_spend();
    }

    // Valid prefix followed by a half-written line, as a crash would leave it.
    let path = journal_path(&dir);
    let mut contents = fs::read_to_string(&path).expect("journal must exist");
    contents.push_str("{\"ts\":\"2026-01-01\",\"kind\":\"spe");
    fs::write(&path, contents).expect("write");

    let err = open_store(&dir).expect_err("a damaged spend journal must not be read as $0 spent");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("spend journal"),
        "the failure must name the spend journal so an operator can fix it, got: {msg}"
    );
}

/// An unreadable journal is equally fatal.
///
/// Distinct from corruption: the bytes are fine, we simply cannot see them.
/// Both fail closed; only genuine *absence* may mean "nothing spent".
#[cfg(unix)]
#[test]
fn unreadable_spend_journal_blocks_startup() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().expect("tempdir");
    {
        let store = open_store(&dir).expect("first open must succeed");
        store.record_spend(None, 7.5, "openai", "gpt-4");
        store.flush_spend();
    }

    let path = journal_path(&dir);
    let mut perms = fs::metadata(&path).expect("metadata").permissions();
    perms.set_mode(0o000);
    fs::set_permissions(&path, perms).expect("chmod");

    let result = open_store(&dir);

    // Restore first so the tempdir can always clean itself up.
    let mut perms = fs::metadata(&path).expect("metadata").permissions();
    perms.set_mode(0o600);
    let _ = fs::set_permissions(&path, perms);

    // Root ignores the permission bit; skip rather than report a false failure.
    if result.is_ok() && std::env::var("USER").as_deref() == Ok("root") {
        return;
    }
    assert!(
        result.is_err(),
        "an unreadable spend journal must block startup, not report $0 spent"
    );
}

/// The legitimate case: no journal yet means no spend yet.
///
/// The fix must not overshoot into refusing a clean first run.
#[test]
fn absent_spend_journal_starts_clean() {
    let dir = TempDir::new().expect("tempdir");
    let store = open_store(&dir).expect("a fresh install must start");
    assert_eq!(
        store.load_spend().total,
        0.0,
        "a first run has spent nothing"
    );
}

/// Recorded spend must survive a restart.
///
/// Without this, "fail closed" could be satisfied trivially by always reading
/// zero and never persisting anything.
#[test]
fn spend_survives_restart() {
    let dir = TempDir::new().expect("tempdir");
    {
        let store = open_store(&dir).expect("open");
        store.record_spend(None, 12.25, "anthropic", "claude-sonnet");
        store.flush_spend();
    }
    let store = open_store(&dir).expect("reopen");
    assert!(
        (store.load_spend().total - 12.25).abs() < 1e-9,
        "spend must be replayed from the journal after a restart"
    );
}

/// Per-tenant reads fail closed too.
///
/// The tenant path can reach the journal at request time (on a cache miss), so
/// it is the authorizing read that outlives startup and must be denied at
/// dispatch rather than answered with a zero.
#[test]
fn corrupt_journal_denies_tenant_spend_read() {
    let dir = TempDir::new().expect("tempdir");
    let store = open_store(&dir).expect("open");
    store.record_spend(Some("tenant-a"), 5.0, "anthropic", "claude-opus");
    store.flush_spend();

    let path = journal_path(&dir);
    let mut contents = fs::read_to_string(&path).expect("journal");
    contents.push_str("{not json\n");
    fs::write(&path, contents).expect("write");

    // A tenant unseen in this process misses the cache and hits the journal.
    let result = store.load_tenant_spend("tenant-never-seen");
    assert!(
        result.is_err(),
        "a damaged journal must deny the tenant spend read, not answer $0"
    );
}

// ── Observing: must NOT block ────────────────────────────────────

/// Observing dependencies must not stop a read.
///
/// Asserted so a later "make everything fail closed" change cannot cross the
/// line in the other direction, trading a spend leak for an availability
/// outage. No metrics recorder or audit sink is installed in this test binary,
/// and the read must still answer.
#[test]
fn observing_dependencies_do_not_block_reads() {
    let dir = TempDir::new().expect("tempdir");
    let store = open_store(&dir).expect("open");
    store.record_spend(None, 1.0, "anthropic", "claude-opus");

    assert!(
        (store.load_spend().total - 1.0).abs() < 1e-9,
        "a read must not depend on metrics or audit being available"
    );
}

// ── Shared storage is not shared state ───────────────────────────

/// Two live processes over one storage dir do NOT see each other's spend.
///
/// This is the boundary that decides whether a budget is a fleet-wide cap or a
/// per-replica one. The in-memory total is seeded once at open and updated only
/// by this process, so a peer writing to the same journal stays invisible until
/// restart. Mounting a shared volume therefore does **not** make the budget
/// shared, which is exactly the assumption an operator is likely to make.
#[test]
fn spend_is_not_shared_between_live_stores() {
    let dir = TempDir::new().expect("tempdir");

    // Two stores over the same directory: two replicas on one volume.
    let a = open_store(&dir).expect("store a");
    let b = open_store(&dir).expect("store b");

    a.record_spend(None, 10.0, "anthropic", "claude-opus");
    a.flush_spend();

    assert!(
        (a.load_spend().total - 10.0).abs() < 1e-9,
        "the writing replica sees its own spend"
    );
    assert_eq!(
        b.load_spend().total,
        0.0,
        "a live peer does NOT see it: caches are per process, so a budget binds \
         per replica even on shared storage"
    );

    // A restart does pick it up, which is what makes the journal the record.
    let c = open_store(&dir).expect("store c");
    assert!(
        (c.load_spend().total - 10.0).abs() < 1e-9,
        "a fresh process replays the journal and sees the peer's spend"
    );
}

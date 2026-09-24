//! Fault injection uses child test processes; production binaries contain no hooks.

use super::GrobStore;
use crate::auth::{token_store::OAuthToken, OAuthClient, OAuthConfig, TokenStore};
use chrono::Utc;
use secrecy::{ExposeSecret, SecretString};
use std::{path::Path, process::Command, sync::Arc, time::Duration};

pub(crate) fn checkpoint(point: &str) {
    if std::env::var("GROB_TEST_CHECKPOINT").as_deref() != Ok(point) {
        return;
    }
    let signal = std::path::PathBuf::from(std::env::var_os("GROB_TEST_SIGNAL").unwrap());
    std::fs::write(&signal, point).unwrap();
    if std::env::var("GROB_TEST_VM_CUT").as_deref() == Ok("1") {
        // The host kills the whole guest here, including its kernel page cache.
        use std::io::Write;
        println!("GROB_VM_CUT_READY:{point}");
        std::io::stdout().flush().unwrap();
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while !signal.with_extension("continue").exists() {
        assert!(std::time::Instant::now() < deadline, "checkpoint timed out");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn token(value: &str) -> OAuthToken {
    OAuthToken {
        provider_id: "provider".into(),
        access_token: SecretString::from(value),
        refresh_token: SecretString::from("synthetic-refresh"),
        expires_at: Utc::now() - chrono::Duration::minutes(1),
        enterprise_url: None,
        project_id: None,
        needs_reauth: None,
    }
}

#[test]
fn child() {
    let Some(root) = std::env::var_os("GROB_TEST_ROOT") else {
        return;
    };
    let root = Path::new(&root);
    let store = Arc::new(GrobStore::open(&root.join("grob.db")).unwrap());
    match std::env::var("GROB_TEST_ACTION").unwrap().as_str() {
        "secret" => store.set_secret("live", "synthetic-new").unwrap(),
        "rotate" => {
            let old = store.list_virtual_keys().pop().unwrap();
            store.rotate_virtual_key(&old.id).unwrap();
        }
        "torn-spend" => {
            use std::io::Write;
            let month = crate::features::token_pricing::spend::current_month();
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(root.join("spend").join(format!("{month}.jsonl")))
                .unwrap();
            file.write_all(b"{\"cost_usd\":").unwrap();
            file.sync_all().unwrap();
            checkpoint("journal-torn");
        }
        "delete" => {
            store.delete_oauth_token("provider").unwrap();
            checkpoint("deleted");
        }
        "spend" => {
            store.record_spend(None, 0.25, "provider", "model");
            store.flush_spend();
            checkpoint("spend-flushed");
        }
        "refresh" => {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let mut config = OAuthConfig::openai_codex();
            config.token_url = std::env::var("GROB_TEST_ISSUER").unwrap();
            let client = OAuthClient::new(config, TokenStore::with_store(store).unwrap());
            let result = runtime.block_on(client.refresh_token("provider"));
            let output = match result {
                Ok(token) => token.access_token.expose_secret().to_owned(),
                Err(error) => format!("error: {error:#}"),
            };
            std::fs::write(std::env::var_os("GROB_TEST_OUTPUT").unwrap(), output).unwrap();
        }
        action => panic!("unknown child action: {action}"),
    }
}

struct Child(std::process::Child);

impl Child {
    fn spawn(root: &Path, name: &str, action: &str, point: &str, issuer: &str) -> Self {
        Self(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "storage::process_tests::child", "--nocapture"])
                .env("GROB_TEST_ROOT", root)
                .env("GROB_TEST_ACTION", action)
                .env("GROB_TEST_CHECKPOINT", point)
                .env("GROB_TEST_SIGNAL", root.join(format!("{name}.signal")))
                .env("GROB_TEST_OUTPUT", root.join(format!("{name}.out")))
                .env("GROB_TEST_ISSUER", issuer)
                .spawn()
                .unwrap(),
        )
    }

    async fn completed(&mut self) {
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if let Some(status) = self.0.try_wait().unwrap() {
                    assert!(status.success());
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("child did not exit");
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn signaled(root: &Path, name: &str) {
    tokio::time::timeout(Duration::from_secs(15), async {
        while !root.join(format!("{name}.signal")).is_file() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("child never reached checkpoint");
}

fn resume(root: &Path, name: &str) {
    std::fs::write(root.join(name).with_extension("continue"), []).unwrap();
}

struct Issuer {
    requests: std::sync::atomic::AtomicUsize,
    release: tokio::sync::Semaphore,
}

impl Issuer {
    async fn start() -> (Arc<Self>, String, tokio::task::JoinHandle<()>) {
        use axum::{extract::State, routing::post, Json, Router};
        let issuer = Arc::new(Self {
            requests: std::sync::atomic::AtomicUsize::new(0),
            release: tokio::sync::Semaphore::new(0),
        });
        let app = Router::new()
            .route(
                "/token",
                post(|State(state): State<Arc<Self>>, body: String| async move {
                    use std::sync::atomic::Ordering::SeqCst;
                    assert!(body.contains("synthetic-refresh"));
                    let attempt = state.requests.fetch_add(1, SeqCst);
                    let permit = state.release.acquire().await.unwrap();
                    permit.forget();
                    if attempt > 0 {
                        return (axum::http::StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"invalid_grant"})));
                    }
                    (axum::http::StatusCode::OK, Json(serde_json::json!({
                        "access_token":"synthetic-issued", "refresh_token":"synthetic-rotated", "expires_in":3600
                    })))
                }),
            )
            .with_state(issuer.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/token", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (issuer, url, task)
    }

    async fn requested(&self) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while self.count() == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }

    fn count(&self) -> usize {
        self.requests.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[tokio::test]
async fn independent_processes_refresh_once_against_rotating_issuer() {
    let root = tempfile::tempdir().unwrap();
    let store = GrobStore::open(&root.path().join("grob.db")).unwrap();
    store.save_oauth_token(&token("synthetic-old")).unwrap();
    let (issuer, url, server) = Issuer::start().await;
    let mut first = Child::spawn(root.path(), "first", "refresh", "refresh-waiting", &url);
    let mut second = Child::spawn(root.path(), "second", "refresh", "refresh-waiting", &url);
    signaled(root.path(), "first").await;
    signaled(root.path(), "second").await;
    resume(root.path(), "first");
    issuer.requested().await;
    resume(root.path(), "second");
    issuer.release.add_permits(2);
    first.completed().await;
    second.completed().await;
    assert_eq!(issuer.count(), 1);
    for name in ["first", "second"] {
        assert_eq!(
            std::fs::read_to_string(root.path().join(format!("{name}.out"))).unwrap(),
            "synthetic-issued"
        );
    }
    server.abort();
}

#[tokio::test]
async fn replacement_and_deletion_win_over_an_inflight_process_refresh() {
    for delete in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let store = GrobStore::open(&root.path().join("grob.db")).unwrap();
        store.save_oauth_token(&token("synthetic-old")).unwrap();
        let (issuer, url, server) = Issuer::start().await;
        let mut child = Child::spawn(root.path(), "refresh", "refresh", "unused", &url);
        issuer.requested().await;
        if delete {
            store.delete_oauth_token("provider").unwrap();
        } else {
            store.save_oauth_token(&token("synthetic-manual")).unwrap();
        }
        issuer.release.add_permits(1);
        child.completed().await;
        let output = std::fs::read_to_string(root.path().join("refresh.out")).unwrap();
        if delete {
            assert!(output.contains("Token removed during refresh"));
            assert!(store.get_oauth_token("provider").is_none());
        } else {
            assert_eq!(output, "synthetic-manual");
            assert_eq!(
                store
                    .get_oauth_token("provider")
                    .unwrap()
                    .access_token
                    .expose_secret(),
                output
            );
        }
        server.abort();
    }
}

#[tokio::test]
async fn killed_refresh_releases_lease_but_never_reuses_an_uncertain_token() {
    let root = tempfile::tempdir().unwrap();
    let store = GrobStore::open(&root.path().join("grob.db")).unwrap();
    store.save_oauth_token(&token("synthetic-old")).unwrap();
    let (issuer, url, server) = Issuer::start().await;
    issuer.release.add_permits(2);
    let child = Child::spawn(root.path(), "first", "refresh", "refresh-received", &url);
    signaled(root.path(), "first").await;
    drop(child);
    let mut next = Child::spawn(root.path(), "next", "refresh", "unused", &url);
    next.completed().await;
    assert!(std::fs::read_to_string(root.path().join("next.out"))
        .unwrap()
        .contains("outcome is unknown"));
    assert_eq!(issuer.count(), 1);
    assert_eq!(
        store
            .get_oauth_token("provider")
            .unwrap()
            .access_token
            .expose_secret(),
        "synthetic-old"
    );
    server.abort();
}

#[tokio::test]
async fn abrupt_exit_at_every_atomic_publish_boundary_keeps_authenticated_records() {
    for (point, expected) in [
        ("atomic-written", "synthetic-old"),
        ("atomic-synced", "synthetic-old"),
        ("atomic-renamed", "synthetic-new"),
        ("atomic-published", "synthetic-new"),
    ] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("grob.db");
        GrobStore::open(&path)
            .unwrap()
            .set_secret("live", "synthetic-old")
            .unwrap();
        let child = Child::spawn(root.path(), "writer", "secret", point, "");
        signaled(root.path(), "writer").await;
        drop(child);
        let recovered = GrobStore::open(&path).unwrap();
        assert_eq!(
            recovered.get_secret("live").unwrap().expose_secret(),
            expected
        );
        for entry in std::fs::read_dir(root.path().join("secrets")).unwrap() {
            let bytes = std::fs::read(entry.unwrap().path()).unwrap();
            assert!(!bytes.windows(10).any(|part| part == b"synthetic-"));
        }
    }
}

#[tokio::test]
async fn acknowledged_deletion_and_flushed_spend_survive_abrupt_exit() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("grob.db");
    GrobStore::open(&path)
        .unwrap()
        .save_oauth_token(&token("synthetic-old"))
        .unwrap();
    let child = Child::spawn(root.path(), "delete", "delete", "deleted", "");
    signaled(root.path(), "delete").await;
    drop(child);
    assert!(GrobStore::open(&path)
        .unwrap()
        .get_oauth_token("provider")
        .is_none());
    let child = Child::spawn(root.path(), "spend", "spend", "spend-flushed", "");
    signaled(root.path(), "spend").await;
    drop(child);
    assert_eq!(GrobStore::open(&path).unwrap().load_spend().total, 0.25);
}

#[tokio::test]
async fn cancelled_waiter_does_not_hold_a_lease_or_block_other_credentials() {
    let root = tempfile::tempdir().unwrap();
    let store = GrobStore::open(&root.path().join("grob.db")).unwrap();
    let first = store.lock_oauth_refresh("provider").await.unwrap();
    assert!(tokio::time::timeout(
        Duration::from_millis(75),
        store.lock_oauth_refresh("provider")
    )
    .await
    .is_err());
    drop(store.lock_oauth_refresh("independent").await.unwrap());
    drop(first);
    tokio::time::timeout(Duration::from_secs(1), store.lock_oauth_refresh("provider"))
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn interrupted_rotation_never_reactivates_a_revoked_key() {
    for point in ["rotation-replacement", "rotation-revoked"] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("grob.db");
        let old = super::credential_tests::key();
        GrobStore::open(&path)
            .unwrap()
            .store_virtual_key(&old)
            .unwrap();
        let child = Child::spawn(root.path(), "rotate", "rotate", point, "");
        signaled(root.path(), "rotate").await;
        drop(child);
        let store = GrobStore::open(&path).unwrap();
        assert_eq!(
            store.lookup_virtual_key(&old.key_hash).unwrap().revoked,
            point == "rotation-revoked"
        );
        let records = store.list_virtual_keys();
        assert_eq!(records.len(), 2);
        let new = records.iter().find(|record| record.id != old.id).unwrap();
        assert_eq!(new.expires_at, old.expires_at);
        assert_eq!(new.allowed_providers, old.allowed_providers);
    }
}

#[tokio::test]
async fn journal_crash_boundaries_have_explicit_recovery_outcomes() {
    for (point, expected) in [("journal-before-append", 0.0), ("journal-appended", 0.25)] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("grob.db");
        GrobStore::open(&path).unwrap();
        let child = Child::spawn(root.path(), "writer", "spend", point, "");
        signaled(root.path(), "writer").await;
        drop(child);
        assert_eq!(GrobStore::open(&path).unwrap().load_spend().total, expected);
    }
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("grob.db");
    GrobStore::open(&path).unwrap();
    let child = Child::spawn(root.path(), "writer", "torn-spend", "journal-torn", "");
    signaled(root.path(), "writer").await;
    drop(child);
    let error = GrobStore::open(&path).unwrap_err();
    assert!(format!("{error:#}").contains("malformed spend journal"));
}

#[tokio::test]
async fn lease_wait_has_a_bounded_timeout() {
    let root = tempfile::tempdir().unwrap();
    let store = GrobStore::open(&root.path().join("grob.db")).unwrap();
    let _holder = store.lock_oauth_refresh("provider").await.unwrap();
    let error = tokio::time::timeout(
        Duration::from_secs(35),
        store.lock_oauth_refresh("provider"),
    )
    .await
    .expect("lease wait exceeded its deadline")
    .unwrap_err();
    assert!(error.to_string().contains("Timed out"));
}

#[tokio::test]
async fn cancelling_the_issuer_request_requires_replacement_before_retry() {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(GrobStore::open(&root.path().join("grob.db")).unwrap());
    store.save_oauth_token(&token("synthetic-old")).unwrap();
    let (issuer, url, server) = Issuer::start().await;
    let mut config = OAuthConfig::openai_codex();
    config.token_url = url;
    let tokens = TokenStore::with_store(store.clone()).unwrap();
    let client = Arc::new(OAuthClient::new(config, tokens));
    let running_client = client.clone();
    let refresh = tokio::spawn(async move { running_client.refresh_token("provider").await });
    issuer.requested().await;
    refresh.abort();
    assert!(refresh.await.unwrap_err().is_cancelled());
    let mut changed_metadata = store.get_oauth_token("provider").unwrap();
    changed_metadata.needs_reauth = Some(true);
    changed_metadata.project_id = Some("changed-project".into());
    store.save_oauth_token(&changed_metadata).unwrap();
    let error = client.refresh_token("provider").await.unwrap_err();
    assert!(error.to_string().contains("outcome is unknown"));
    assert!(crate::auth::refresh_daemon::classify_refresh_error(&error.to_string()).is_terminal());
    assert_eq!(issuer.count(), 1);
    server.abort();

    // A separately acquired credential supersedes the old uncertainty marker.
    let mut replacement = token("synthetic-replacement");
    replacement.refresh_token = SecretString::from("synthetic-refresh-replacement");
    store.save_oauth_token(&replacement).unwrap();
    let (issuer, url, server) = Issuer::start().await;
    issuer.release.add_permits(1);
    let mut config = OAuthConfig::openai_codex();
    config.token_url = url;
    let client = OAuthClient::new(config, TokenStore::with_store(store.clone()).unwrap());
    assert_eq!(
        client
            .refresh_token("provider")
            .await
            .unwrap()
            .access_token
            .expose_secret(),
        "synthetic-issued"
    );
    assert!(!root.path().join("tokens/provider.refresh.pending").exists());
    server.abort();
}

#[tokio::test]
async fn only_definitive_auth_rejection_clears_refresh_intent() {
    for status in [400, 401, 403, 500, 502] {
        let root = tempfile::tempdir().unwrap();
        let store = Arc::new(GrobStore::open(&root.path().join("grob.db")).unwrap());
        store.save_oauth_token(&token("synthetic-old")).unwrap();
        let mut issuer = mockito::Server::new_async().await;
        let rejection = issuer
            .mock("POST", "/token")
            .with_status(status)
            .with_body("synthetic-sensitive-error-body")
            .expect(1)
            .create_async()
            .await;
        let mut config = OAuthConfig::openai_codex();
        config.token_url = format!("{}/token", issuer.url());
        let client = OAuthClient::new(config, TokenStore::with_store(store).unwrap());
        let error = client.refresh_token("provider").await.unwrap_err();
        assert!(!error.to_string().contains("synthetic-sensitive"));
        assert_eq!(
            root.path().join("tokens/provider.refresh.pending").exists(),
            status >= 500
        );
        rejection.assert_async().await;
    }
}

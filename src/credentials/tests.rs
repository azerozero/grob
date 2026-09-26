use super::{
    broker::Broker,
    config::{Injection, ServiceBinding, VaultConfig},
    record::{Authority, Bundle, CredentialRecord},
    *,
};
use crate::storage::GrobStore;
use std::sync::Arc;

fn fixture() -> (tempfile::TempDir, Arc<GrobStore>, ServiceBinding) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(GrobStore::open(&dir.path().join("grob.db")).unwrap());
    let binding = ServiceBinding {
        id: "service".into(),
        tenant: "tenant/a".into(),
        agents: vec![format!("key:{}", uuid::Uuid::new_v4())],
        origin: "https://service.example".into(),
        allowed_ips: vec!["203.0.113.1".parse().unwrap()],
        paths: vec!["/test".into()],
        methods: vec!["GET".into()],
        injection: Injection::Bearer,
        expires_at: None,
        vault: None,
    };
    (dir, store, binding)
}

fn local(binding: &ServiceBinding, value: &str) -> CredentialRecord {
    CredentialRecord::provision(
        binding,
        Authority::Local,
        Some(Bundle {
            token: value.into(),
            username: String::new(),
            password: String::new(),
        }),
        None,
    )
}

#[tokio::test]
async fn scope_integrity_revocation_and_late_publication_survive_reopen() {
    let (dir, store, binding) = fixture();
    store.set_secret("service", "synthetic-global").unwrap();
    assert!(Broker::new(&binding)
        .unwrap()
        .resolve(store.clone())
        .await
        .is_err());
    store
        .credential_publish(local(&binding, "synthetic-local"), None)
        .unwrap();
    let old = store.credential_read(&binding.tenant, &binding.id).unwrap();
    assert!(store.credential_read("tenant_a", &binding.id).is_err());
    store
        .credential_revoke(&binding.tenant, &binding.id)
        .unwrap();
    assert!(matches!(
        store.credential_publish(old.clone(), Some(old.generation)),
        Err(CredentialError::Changed)
    ));
    let reopened = Arc::new(GrobStore::open(&dir.path().join("grob.db")).unwrap());
    assert!(Broker::new(&binding)
        .unwrap()
        .resolve(reopened.clone())
        .await
        .is_err());
    let path = std::fs::read_dir(dir.path().join("credentials"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    std::fs::write(path, br#"{"token":"synthetic-global"}"#).unwrap();
    assert!(Broker::new(&binding)
        .unwrap()
        .resolve(reopened)
        .await
        .is_err());
}

#[tokio::test]
async fn expiry_policy_changes_and_clock_rollback_fail_closed() {
    let (_dir, store, mut binding) = fixture();
    let mut record = local(&binding, "synthetic-local");
    record.expires_at = Some(now() - 1);
    store.credential_publish(record, None).unwrap();
    assert!(Broker::new(&binding)
        .unwrap()
        .resolve(store.clone())
        .await
        .is_err());
    let mut record = local(&binding, "synthetic-local");
    record.observed_at = now() + 60;
    store.credential_publish(record, None).unwrap();
    assert!(Broker::new(&binding)
        .unwrap()
        .resolve(store.clone())
        .await
        .is_err());
    store
        .credential_publish(local(&binding, "synthetic-local"), None)
        .unwrap();
    binding.origin = "https://other.example".into();
    assert!(Broker::new(&binding).unwrap().resolve(store).await.is_err());
}

#[test]
fn rejects_ambiguous_destinations_and_pins_dns_independently_of_agent_input() {
    let (_dir, _store, mut binding) = fixture();
    binding.validate().unwrap();
    for path in [
        "//test",
        "/../test",
        "/%2e/test",
        "/test?token=x",
        "/test\\other",
    ] {
        binding.paths = vec![path.into()];
        assert!(binding.validate().is_err(), "{path}");
    }
    binding.paths = vec!["/test".into()];
    for origin in [
        "http://service.example",
        "https://user:password@service.example",
        "https://service.example/path",
        "http://localhost.evil.example",
        "https://127.0.0.1",
    ] {
        binding.origin = origin.into();
        assert!(binding.validate().is_err(), "{origin}");
    }
}

async fn vault_fixture(
    server: &mockito::Server,
) -> (tempfile::TempDir, Arc<GrobStore>, ServiceBinding) {
    let (dir, store, mut binding) = fixture();
    let token_file = dir.path().join("vault-token");
    std::fs::write(&token_file, "synthetic-vault-token").unwrap();
    crate::auth::token_store::set_owner_only_permissions(&token_file).unwrap();
    binding.vault = Some(VaultConfig {
        endpoint: format!("{}/v1/secret/data/service", server.url()),
        allowed_ips: vec!["127.0.0.1".parse().unwrap()],
        token_file,
        proxy_socket: None,
        refresh_secs: 1,
        max_offline_secs: 30,
    });
    store
        .credential_publish(
            CredentialRecord::provision(&binding, Authority::Vault, None, None),
            None,
        )
        .unwrap();
    (dir, store, binding)
}

fn remote_body(version: u64) -> String {
    serde_json::json!({"data":{"data":{"token":format!("synthetic-remote-{version}")},"metadata":{"version":version,"destroyed":false,"deletion_time":""}}}).to_string()
}

fn force_refresh(store: &GrobStore, binding: &ServiceBinding) {
    let mut record = store.credential_read(&binding.tenant, &binding.id).unwrap();
    record.retry_at = 0;
    store.credential_publish(record, None).unwrap();
}

#[tokio::test]
async fn vault_recovery_is_bounded_and_authority_can_switch_live() {
    let mut server = mockito::Server::new_async().await;
    let (dir, store, binding) = vault_fixture(&server).await;
    let good = server
        .mock("GET", "/v1/secret/data/service")
        .match_header("x-vault-token", "synthetic-vault-token")
        .with_body(remote_body(2))
        .create_async()
        .await;
    let first = Broker::new(&binding)
        .unwrap()
        .resolve(store.clone())
        .await
        .unwrap();
    assert_eq!(first.bundle.unwrap().token, "synthetic-remote-2");
    good.assert_async().await;
    good.remove_async().await;
    force_refresh(&store, &binding);
    let outage = server
        .mock("GET", "/v1/secret/data/service")
        .with_status(502)
        .create_async()
        .await;
    let recovered = Broker::new(&binding)
        .unwrap()
        .resolve(store.clone())
        .await
        .unwrap();
    assert!(recovered.recovery);
    assert_eq!(recovered.verified_at, first.verified_at);
    outage.assert_async().await;
    let reopened = Arc::new(GrobStore::open(&dir.path().join("grob.db")).unwrap());
    assert!(
        Broker::new(&binding)
            .unwrap()
            .resolve(reopened.clone())
            .await
            .unwrap()
            .recovery
    );
    let mut expired = reopened
        .credential_read(&binding.tenant, &binding.id)
        .unwrap();
    expired.verified_at = Some(now() - 31);
    reopened.credential_publish(expired, None).unwrap();
    assert!(Broker::new(&binding)
        .unwrap()
        .resolve(reopened.clone())
        .await
        .is_err());
    reopened
        .credential_publish(local(&binding, "synthetic-emergency"), None)
        .unwrap();
    let local = Broker::new(&binding)
        .unwrap()
        .resolve(reopened)
        .await
        .unwrap();
    assert_eq!(local.authority, Authority::Local);
    assert_eq!(local.bundle.unwrap().token, "synthetic-emergency");
}

#[tokio::test]
async fn vault_denials_malformed_data_and_version_rollback_disable_snapshots() {
    for (status, body) in [
        (401, "{}".into()),
        (403, "{}".into()),
        (404, "{}".into()),
        (503, r#"{"errors":["Vault is sealed"]}"#.into()),
        (200, "broken".into()),
        (200, remote_body(1)),
    ] {
        let mut server = mockito::Server::new_async().await;
        let (_dir, store, binding) = vault_fixture(&server).await;
        let good = server
            .mock("GET", "/v1/secret/data/service")
            .with_body(remote_body(2))
            .create_async()
            .await;
        Broker::new(&binding)
            .unwrap()
            .resolve(store.clone())
            .await
            .unwrap();
        good.remove_async().await;
        force_refresh(&store, &binding);
        let denied = server
            .mock("GET", "/v1/secret/data/service")
            .with_status(status)
            .with_body(body)
            .create_async()
            .await;
        assert!(Broker::new(&binding)
            .unwrap()
            .resolve(store.clone())
            .await
            .is_err());
        assert!(
            store
                .credential_read(&binding.tenant, &binding.id)
                .unwrap()
                .revoked
        );
        denied.assert_async().await;
    }
}

#[tokio::test]
async fn outage_without_snapshot_or_opt_in_never_grants_dispatch() {
    let mut server = mockito::Server::new_async().await;
    let (_dir, store, mut binding) = vault_fixture(&server).await;
    let outage = server
        .mock("GET", "/v1/secret/data/service")
        .with_status(504)
        .create_async()
        .await;
    assert!(Broker::new(&binding)
        .unwrap()
        .resolve(store.clone())
        .await
        .is_err());
    outage.remove_async().await;
    binding.vault.as_mut().unwrap().max_offline_secs = 0;
    store
        .credential_publish(
            CredentialRecord::provision(&binding, Authority::Vault, None, None),
            None,
        )
        .unwrap();
    let good = server
        .mock("GET", "/v1/secret/data/service")
        .with_body(remote_body(2))
        .create_async()
        .await;
    Broker::new(&binding)
        .unwrap()
        .resolve(store.clone())
        .await
        .unwrap();
    good.remove_async().await;
    force_refresh(&store, &binding);
    let outage = server
        .mock("GET", "/v1/secret/data/service")
        .with_status(502)
        .create_async()
        .await;
    assert!(Broker::new(&binding).unwrap().resolve(store).await.is_err());
    outage.assert_async().await;
}

#[test]
fn concurrent_bundle_rotation_never_mixes_fields_between_independent_handles() {
    let (dir, store, mut binding) = fixture();
    binding.injection = Injection::Basic;
    let bundle = |index| {
        CredentialRecord::provision(
            &binding,
            Authority::Local,
            Some(Bundle {
                token: String::new(),
                username: format!("user-{index}"),
                password: format!("password-{index}"),
            }),
            None,
        )
    };
    store.credential_publish(bundle(0), None).unwrap();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let writer = GrobStore::open(&dir.path().join("grob.db")).unwrap();
            for i in 1..100 {
                writer.credential_publish(bundle(i), None).unwrap();
            }
        });
        for _ in 0..100 {
            let bundle = store
                .credential_read(&binding.tenant, &binding.id)
                .unwrap()
                .bundle
                .unwrap();
            assert_eq!(
                bundle.username.strip_prefix("user-"),
                bundle.password.strip_prefix("password-")
            );
        }
    });
}

#[test]
fn local_rotation_preserves_expiry_until_explicitly_changed() {
    let (_dir, store, binding) = fixture();
    let token = || Bundle {
        token: "synthetic-rotation".into(),
        username: String::new(),
        password: String::new(),
    };
    let deadline = now() + 600;
    store
        .credential_set_local(&binding, token(), Some(deadline))
        .unwrap();
    store.credential_set_local(&binding, token(), None).unwrap();
    assert_eq!(
        store
            .credential_read(&binding.tenant, &binding.id)
            .unwrap()
            .expires_at,
        Some(deadline)
    );
    store
        .credential_revoke(&binding.tenant, &binding.id)
        .unwrap();
    store.credential_set_local(&binding, token(), None).unwrap();
    assert_eq!(
        store
            .credential_read(&binding.tenant, &binding.id)
            .unwrap()
            .expires_at,
        Some(deadline)
    );
    store
        .credential_set_local(&binding, token(), Some(deadline + 600))
        .unwrap();
    assert_eq!(
        store
            .credential_read(&binding.tenant, &binding.id)
            .unwrap()
            .expires_at,
        Some(deadline + 600)
    );
    assert!(store
        .credential_set_local(&binding, token(), Some(now() - 1))
        .is_err());
}

#[test]
fn vault_token_validation_is_shared_with_diagnostics_and_never_echoes_input() {
    for bytes in [
        b"".as_slice(),
        b"\r\n",
        b"invalid\nsynthetic-secret",
        b"\xff",
    ] {
        let error = broker::vault_token_header(bytes).unwrap_err().to_string();
        assert!(!error.contains("synthetic-secret"));
    }
    let header = broker::vault_token_header(b"synthetic-token\n").unwrap();
    assert_eq!(header, "synthetic-token");
    assert!(header.is_sensitive());
}

#[cfg(unix)]
#[tokio::test]
async fn unix_proxy_uses_auto_auth_without_token_file_and_denials_revoke() {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicBool, Ordering};
    let (_dir, store, mut binding) = fixture();
    let sockets = tempfile::Builder::new()
        .prefix("grob-proxy-")
        .tempdir_in("/tmp")
        .unwrap();
    let path = sockets.path().join("proxy.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let deny = Arc::new(AtomicBool::new(false));
    let flag = deny.clone();
    let app = axum::Router::new().route(
        "/v1/secret/data/service",
        axum::routing::get(move |headers: axum::http::HeaderMap| {
            let flag = flag.clone();
            async move {
                assert_eq!(headers["x-vault-request"], "true");
                assert!(!headers.contains_key("x-vault-token"));
                if flag.load(Ordering::SeqCst) {
                    (axum::http::StatusCode::FORBIDDEN, "{}".into())
                } else {
                    (axum::http::StatusCode::OK, remote_body(2))
                }
            }
        }),
    );
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    binding.vault = Some(VaultConfig {
        endpoint: "http://localhost/v1/secret/data/service".into(),
        allowed_ips: vec!["127.0.0.1".parse().unwrap()],
        token_file: Default::default(),
        proxy_socket: Some(path.clone()),
        refresh_secs: 1,
        max_offline_secs: 30,
    });
    binding.validate().unwrap();
    store
        .credential_publish(
            CredentialRecord::provision(&binding, Authority::Vault, None, None),
            None,
        )
        .unwrap();
    let broker = Broker::new(&binding).unwrap();
    let verified = broker.resolve(store.clone()).await.unwrap();
    assert_eq!(verified.bundle.unwrap().token, "synthetic-remote-2");
    deny.store(true, Ordering::SeqCst);
    force_refresh(&store, &binding);
    assert!(broker.resolve(store.clone()).await.is_err());
    assert!(
        store
            .credential_read(&binding.tenant, &binding.id)
            .unwrap()
            .revoked
    );
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(transport::check_proxy_socket(&path).is_err());
    binding.vault.as_mut().unwrap().token_file = "/tmp/token".into();
    assert!(binding.validate().is_err());
    server.abort();
}

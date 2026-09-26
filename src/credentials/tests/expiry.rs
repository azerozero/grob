use super::*;

fn with_expiry(version: u64, expiry: Option<i64>) -> String {
    let mut body: serde_json::Value = serde_json::from_str(&remote_body(version)).unwrap();
    body["data"]["metadata"]["deletion_time"] = expiry
        .map(|t| chrono::DateTime::from_timestamp(t, 0).unwrap().to_rfc3339())
        .unwrap_or_default()
        .into();
    body.to_string()
}

#[tokio::test]
async fn vault_rotation_replaces_version_expiry_and_preserves_administrative_expiry() {
    for successor_expiry in [Some(now() + 3600), None] {
        let mut server = mockito::Server::new_async().await;
        let (dir, store, binding) = vault_fixture(&server).await;
        let admin_expiry = now() + 7200;
        let mut record = store.credential_read(&binding.tenant, &binding.id).unwrap();
        record.expires_at = Some(admin_expiry);
        store.credential_publish(record, None).unwrap();
        let first_expiry = now() + 60;
        let first = server
            .mock("GET", "/v1/secret/data/service")
            .with_body(with_expiry(1, Some(first_expiry)))
            .create_async()
            .await;
        let broker = Broker::new(&binding).unwrap();
        let old = broker.resolve(store.clone()).await.unwrap();
        assert_eq!(old.effective_expiry(), Some(first_expiry));
        first.assert_async().await;
        first.remove_async().await;
        force_refresh(&store, &binding);
        let next = server
            .mock("GET", "/v1/secret/data/service")
            .with_body(with_expiry(2, successor_expiry))
            .create_async()
            .await;
        let current = broker.resolve(store.clone()).await.unwrap();
        assert_eq!(current.expires_at, Some(admin_expiry));
        assert_eq!(current.remote_expires_at, successor_expiry);
        assert_eq!(
            current.effective_expiry(),
            successor_expiry.or(Some(admin_expiry))
        );
        assert_eq!(current.bundle.unwrap().token, "synthetic-remote-2");
        next.assert_async().await;
        let reopened = GrobStore::open(&dir.path().join("grob.db")).unwrap();
        let persisted = reopened
            .credential_read(&binding.tenant, &binding.id)
            .unwrap();
        assert_eq!(persisted.expires_at, Some(admin_expiry));
        assert_eq!(persisted.remote_expires_at, successor_expiry);
    }
}

#[tokio::test]
async fn expired_cached_version_refreshes_but_never_dispatches_during_outage() {
    for outage in [false, true] {
        let mut server = mockito::Server::new_async().await;
        let (_dir, store, binding) = vault_fixture(&server).await;
        let mut record = local(&binding, "synthetic-expired");
        record.authority = Authority::Vault;
        record.remote_version = 1;
        record.remote_expires_at = Some(now() - 1);
        record.verified_at = Some(now());
        record.retry_at = now() + 60;
        store.credential_publish(record, None).unwrap();
        let remote = server
            .mock("GET", "/v1/secret/data/service")
            .with_status(if outage { 502 } else { 200 })
            .with_body(remote_body(2))
            .expect(1)
            .create_async()
            .await;
        let broker = Broker::new(&binding).unwrap();
        let resolved = broker.resolve(store.clone()).await;
        if outage {
            assert!(resolved.is_err());
            // Backoff still applies when the expired cache cannot provide recovery.
            let mut record = store.credential_read(&binding.tenant, &binding.id).unwrap();
            assert!(record.recovery);
            record.retry_at = now() + 60;
            store.credential_publish(record, None).unwrap();
            assert!(broker.resolve(store).await.is_err());
        } else {
            let record = resolved.unwrap();
            assert_eq!(record.bundle.unwrap().token, "synthetic-remote-2");
            assert_eq!(record.remote_expires_at, None);
        }
        remote.assert_async().await;
    }
}

#[tokio::test]
async fn expired_policy_or_revocation_cannot_be_cleared_by_remote_refresh() {
    for restriction in ["administrative", "binding", "revoked"] {
        let mut server = mockito::Server::new_async().await;
        let (_dir, store, mut binding) = vault_fixture(&server).await;
        if restriction == "binding" {
            binding.expires_at = Some(now() - 1);
        }
        let mut record = CredentialRecord::provision(&binding, Authority::Vault, None, None);
        record.expires_at = (restriction == "administrative").then(|| now() - 1);
        record.revoked = restriction == "revoked";
        let broker = Broker::new(&binding).unwrap();
        store.credential_publish(record, None).unwrap();
        let remote = server
            .mock("GET", "/v1/secret/data/service")
            .with_body(remote_body(2))
            .expect(0)
            .create_async()
            .await;
        assert!(broker.resolve(store).await.is_err());
        remote.assert_async().await;
    }
}

#[tokio::test]
async fn legacy_combined_expiry_remains_a_restriction_until_explicit_provisioning() {
    let mut server = mockito::Server::new_async().await;
    let (_dir, store, binding) = vault_fixture(&server).await;
    let deadline = now() + 60;
    let mut legacy = serde_json::to_value(CredentialRecord::provision(
        &binding,
        Authority::Vault,
        None,
        Some(deadline),
    ))
    .unwrap();
    legacy["format"] = 1.into();
    legacy.as_object_mut().unwrap().remove("remote_expires_at");
    let record: CredentialRecord = serde_json::from_value(legacy).unwrap();
    assert_eq!(record.remote_expires_at, None);
    store.credential_publish(record, None).unwrap();
    let remote = server
        .mock("GET", "/v1/secret/data/service")
        .with_body(remote_body(2))
        .create_async()
        .await;
    let current = Broker::new(&binding).unwrap().resolve(store).await.unwrap();
    assert_eq!(current.effective_expiry(), Some(deadline));
    assert!(current.check_authority(&binding, deadline).is_err());
    remote.assert_async().await;
}

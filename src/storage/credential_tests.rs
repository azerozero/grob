use super::GrobStore;
use crate::auth::{token_store::OAuthToken, virtual_keys::VirtualKeyRecord, TokenStore};
use chrono::Utc;
use secrecy::{ExposeSecret, SecretString};
use std::sync::Arc;

fn token(value: &str) -> OAuthToken {
    OAuthToken {
        provider_id: "provider".into(),
        access_token: SecretString::from(value),
        refresh_token: SecretString::from("synthetic-refresh"),
        expires_at: Utc::now() + chrono::Duration::hours(1),
        enterprise_url: None,
        project_id: None,
        needs_reauth: None,
    }
}

pub(super) fn key() -> VirtualKeyRecord {
    let (secret, key_hash) = crate::auth::virtual_keys::generate_key();
    VirtualKeyRecord {
        id: uuid::Uuid::new_v4(),
        name: "agent".into(),
        prefix: secret[..12].into(),
        key_hash,
        tenant_id: "tenant".into(),
        budget_usd: Some(2.0),
        rate_limit_rps: Some(3),
        allowed_models: Some(vec!["alpha".into()]),
        allowed_providers: vec!["provider".into()],
        created_at: Utc::now(),
        expires_at: Some(Utc::now() + chrono::Duration::days(1)),
        revoked: false,
        last_used_at: None,
    }
}

#[test]
fn oauth_replacement_and_deletion_are_visible_to_independent_handles() {
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("grob.db");
    let writer = TokenStore::with_store(Arc::new(GrobStore::open(&path).unwrap())).unwrap();
    let reader = TokenStore::with_store(Arc::new(GrobStore::open(&path).unwrap())).unwrap();
    writer.save(token("synthetic-old")).unwrap();
    assert_eq!(
        reader.get("provider").unwrap().access_token.expose_secret(),
        "synthetic-old"
    );
    writer.save(token("synthetic-new")).unwrap();
    assert_eq!(
        reader.get("provider").unwrap().access_token.expose_secret(),
        "synthetic-new"
    );
    assert_eq!(
        reader.all()["provider"].access_token.expose_secret(),
        "synthetic-new"
    );
    writer.remove("provider").unwrap();
    assert!(reader.get("provider").is_none());
    assert!(reader.list_providers().is_empty());
    assert!(reader.all().is_empty());
}

#[test]
fn late_refresh_cannot_overwrite_or_resurrect_a_replaced_token() {
    let home = tempfile::tempdir().unwrap();
    let store = Arc::new(GrobStore::open(&home.path().join("grob.db")).unwrap());
    let tokens = TokenStore::with_store(store.clone()).unwrap();
    let old = token("synthetic-old");
    tokens.save(old.clone()).unwrap();
    let replacement = token("synthetic-explicit-replacement");
    tokens.save(replacement.clone()).unwrap();
    assert!(!tokens
        .replace_if_current(&old, token("synthetic-late-refresh"))
        .unwrap());
    assert_eq!(
        tokens.get("provider").unwrap().access_token.expose_secret(),
        "synthetic-explicit-replacement"
    );
    assert!(tokens
        .replace_if_current(&replacement, token("synthetic-fresh-refresh"))
        .unwrap());
    let latest = tokens.get("provider").unwrap();
    tokens.remove("provider").unwrap();
    assert!(!tokens
        .replace_if_current(&latest, token("synthetic-resurrection"))
        .unwrap());
    assert!(tokens.get("provider").is_none());
}

#[test]
fn rotation_preserves_every_restriction_and_rejects_inactive_keys() {
    let home = tempfile::tempdir().unwrap();
    let store = GrobStore::open(&home.path().join("grob.db")).unwrap();
    let old = key();
    store.store_virtual_key(&old).unwrap();
    let (new, secret) = store.rotate_virtual_key(&old.id).unwrap();
    assert_ne!(old.id, new.id);
    assert_eq!(new.prefix, secret[..12]);
    assert_eq!(old.expires_at, new.expires_at);
    assert_eq!(old.tenant_id, new.tenant_id);
    assert_eq!(old.budget_usd, new.budget_usd);
    assert_eq!(old.rate_limit_rps, new.rate_limit_rps);
    assert_eq!(old.allowed_models, new.allowed_models);
    assert_eq!(old.allowed_providers, new.allowed_providers);
    assert!(store.lookup_virtual_key(&old.key_hash).unwrap().revoked);
    assert!(!store.lookup_virtual_key(&new.key_hash).unwrap().revoked);
    assert!(store.rotate_virtual_key(&old.id).is_err());
    let mut expired = key();
    expired.expires_at = Some(Utc::now() - chrono::Duration::seconds(1));
    store.store_virtual_key(&expired).unwrap();
    assert!(store.rotate_virtual_key(&expired.id).is_err());
}

#[test]
fn concurrent_rotation_has_one_winner() {
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("grob.db");
    let store = GrobStore::open(&path).unwrap();
    let old = key();
    store.store_virtual_key(&old).unwrap();
    let barrier = Arc::new(std::sync::Barrier::new(4));
    let threads: Vec<_> = (0..4)
        .map(|_| {
            let path = path.clone();
            let barrier = barrier.clone();
            let id = old.id;
            std::thread::spawn(move || {
                let store = GrobStore::open(&path).unwrap();
                barrier.wait();
                store.rotate_virtual_key(&id).is_ok()
            })
        })
        .collect();
    assert_eq!(
        threads
            .into_iter()
            .map(|t| usize::from(t.join().unwrap()))
            .sum::<usize>(),
        1
    );
    assert_eq!(
        store
            .list_virtual_keys()
            .iter()
            .filter(|k| !k.revoked)
            .count(),
        1
    );
}

#[test]
fn concurrent_initialization_keeps_one_master_key_and_encrypted_atomic_replacements() {
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("grob.db");
    let barrier = Arc::new(std::sync::Barrier::new(8));
    let threads: Vec<_> = (0..8)
        .map(|i| {
            let path = path.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let store = GrobStore::open(&path).unwrap();
                store
                    .set_secret(&format!("secret-{i}"), "synthetic-old-secret")
                    .unwrap();
            })
        })
        .collect();
    for thread in threads {
        thread.join().unwrap();
    }
    let store = GrobStore::open(&path).unwrap();
    for i in 0..8 {
        let name = format!("secret-{i}");
        assert_eq!(
            store.get_secret(&name).unwrap().expose_secret(),
            "synthetic-old-secret"
        );
        store.set_secret(&name, "synthetic-replacement").unwrap();
        assert_eq!(
            store.get_secret(&name).unwrap().expose_secret(),
            "synthetic-replacement"
        );
        let file = home.path().join("secrets").join(format!("{name}.enc"));
        assert!(!std::fs::read(&file)
            .unwrap()
            .windows(10)
            .any(|w| w == b"synthetic-"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(file).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn failed_rotation_keeps_the_old_key_usable() {
    use std::os::unix::fs::PermissionsExt;
    let home = tempfile::tempdir().unwrap();
    let store = GrobStore::open(&home.path().join("grob.db")).unwrap();
    let old = key();
    store.store_virtual_key(&old).unwrap();
    let directory = home.path().join("vkeys");
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o500)).unwrap();
    let rotated = store.rotate_virtual_key(&old.id);
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    if rotated.is_ok() && std::env::var("USER").as_deref() == Ok("root") {
        return;
    }
    assert!(rotated.is_err());
    assert!(!store.lookup_virtual_key(&old.key_hash).unwrap().revoked);
    assert_eq!(store.list_virtual_keys().len(), 1);
}

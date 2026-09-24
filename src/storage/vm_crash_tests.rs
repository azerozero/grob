//! Guest-side assertions for the disposable QEMU crash-recovery test.

use super::{credential_tests::key, process_tests::checkpoint, GrobStore};
use crate::auth::token_store::OAuthToken;
use chrono::Utc;
use secrecy::{ExposeSecret, SecretString};
use std::{io::Write, path::Path};

fn token() -> OAuthToken {
    OAuthToken {
        provider_id: "provider".into(),
        access_token: SecretString::from("synthetic-access"),
        refresh_token: SecretString::from("synthetic-refresh"),
        expires_at: Utc::now() + chrono::Duration::hours(1),
        enterprise_url: None,
        project_id: None,
        needs_reauth: None,
    }
}

#[test]
#[ignore = "runs only inside the disposable VM from scripts/ci/crash-vm.py"]
fn vm_probe() {
    let phase = std::env::var("GROB_VM_PHASE").unwrap();
    let case = std::env::var("GROB_VM_CASE").unwrap();
    let path = Path::new("/data/store/grob.db");
    if phase == "verify" && case == "journal-torn" {
        let error = GrobStore::open(path).unwrap_err();
        assert!(format!("{error:#}").contains("refusing to start with an unreadable spend journal"));
        return;
    }
    let store = GrobStore::open(path).unwrap();
    match phase.as_str() {
        "prepare" => {
            store.set_secret("live", "synthetic-old").unwrap();
            store.save_oauth_token(&token()).unwrap();
            let old = key();
            store.store_virtual_key(&old).unwrap();
            std::fs::write("/data/old-key-hash", &old.key_hash).unwrap();
            store.record_spend(None, 0.125, "provider", "model");
            store.flush_spend();
        }
        "cut" => {
            std::env::set_var("GROB_TEST_CHECKPOINT", &case);
            // Signal lives in initramfs, not on the disk being tested.
            std::env::set_var("GROB_TEST_SIGNAL", "/tmp/checkpoint.signal");
            std::env::set_var("GROB_TEST_VM_CUT", "1");
            match case.as_str() {
                point if point.starts_with("atomic-") => {
                    store.set_secret("live", "synthetic-new").unwrap();
                }
                "rotation-replacement" | "rotation-revoked" => {
                    let old = store.list_virtual_keys().pop().unwrap();
                    store.rotate_virtual_key(&old.id).unwrap();
                }
                "deleted" => {
                    store.delete_oauth_token("provider").unwrap();
                    checkpoint(&case);
                }
                "refresh-pending" => {
                    store.begin_oauth_refresh(&token()).unwrap();
                    checkpoint(&case);
                }
                "spend-flushed" => {
                    store.record_spend(None, 0.25, "provider", "model");
                    store.flush_spend();
                    checkpoint(&case);
                }
                "journal-torn" => {
                    let month = crate::features::token_pricing::spend::current_month();
                    let mut file = std::fs::OpenOptions::new()
                        .append(true)
                        .open(format!("/data/store/spend/{month}.jsonl"))
                        .unwrap();
                    file.write_all(b"{\"cost_usd\":").unwrap();
                    file.sync_all().unwrap();
                    checkpoint(&case);
                }
                _ => panic!("unknown crash case: {case}"),
            }
            panic!("host did not cut VM power at {case}");
        }
        "verify" => {
            let secret = store
                .get_secret("live")
                .expect("credential must authenticate");
            match case.as_str() {
                "atomic-written" | "atomic-synced" => {
                    assert_eq!(secret.expose_secret(), "synthetic-old");
                }
                "atomic-renamed" => {
                    assert!(matches!(
                        secret.expose_secret(),
                        "synthetic-old" | "synthetic-new"
                    ));
                }
                "atomic-published" => assert_eq!(secret.expose_secret(), "synthetic-new"),
                "deleted" => assert!(store.get_oauth_token("provider").is_none()),
                "rotation-replacement" | "rotation-revoked" => {
                    let hash = std::fs::read_to_string("/data/old-key-hash").unwrap();
                    let old = store.lookup_virtual_key(&hash).unwrap();
                    assert_eq!(old.revoked, case == "rotation-revoked");
                    assert_eq!(store.list_virtual_keys().len(), 2);
                }
                "refresh-pending" => {
                    assert!(store
                        .begin_oauth_refresh(&token())
                        .unwrap_err()
                        .to_string()
                        .contains("outcome is unknown"));
                }
                "spend-flushed" => assert_eq!(store.load_spend().total, 0.375),
                _ => panic!("unknown verification case: {case}"),
            }
        }
        _ => panic!("unknown VM phase: {phase}"),
    }
}

use cucumber::then;
use std::collections::HashSet;

use crate::world::E2eWorld;

/// Resolves the host-side mountpoint of the grob-audit-vol podman volume.
async fn volume_mountpoint() -> String {
    let output = tokio::process::Command::new("podman")
        .args([
            "volume",
            "inspect",
            "grob-audit-vol",
            "--format",
            "{{.Mountpoint}}",
        ])
        .output()
        .await
        .expect("failed to inspect grob-audit-vol");
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

/// Reads audit JSONL directly from the volume mountpoint on the host.
async fn load_audit(world: &mut E2eWorld) {
    let mountpoint = volume_mountpoint().await;
    let path = format!("{mountpoint}/current.jsonl");
    let content = tokio::fs::read_to_string(&path)
        .await
        .unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
    world.audit_lines = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(String::from)
        .collect();
}

#[then(regex = r"the audit file has at least (\d+) entries")]
async fn audit_min_entries(world: &mut E2eWorld, min: usize) {
    load_audit(world).await;
    assert!(
        world.audit_lines.len() >= min,
        "expected >= {min} audit entries, got {}",
        world.audit_lines.len()
    );
}

#[then("all audit entries are valid JSON")]
async fn audit_valid_json(world: &mut E2eWorld) {
    load_audit(world).await;
    for (i, line) in world.audit_lines.iter().enumerate() {
        serde_json::from_str::<serde_json::Value>(line)
            .unwrap_or_else(|e| panic!("audit line {i} is not valid JSON: {e}"));
    }
}

#[then("the signing key exists")]
async fn signing_key_exists(_world: &mut E2eWorld) {
    let mountpoint = volume_mountpoint().await;
    let key_path = format!("{mountpoint}/audit_key.pem");
    let meta = tokio::fs::metadata(&key_path)
        .await
        .unwrap_or_else(|e| panic!("audit_key.pem missing: {e}"));
    assert!(meta.len() > 0, "audit_key.pem is empty");
}

#[then(regex = r#"all audit entries have field "(.+)""#)]
async fn audit_has_field(world: &mut E2eWorld, field: String) {
    load_audit(world).await;
    for (i, line) in world.audit_lines.iter().enumerate() {
        let obj: serde_json::Value = serde_json::from_str(line).unwrap();
        let val = &obj[&field];
        assert!(!val.is_null(), "audit entry {i} missing field '{field}'");
    }
}

#[then("all signature_algorithm values are valid")]
async fn signature_algorithm_valid(world: &mut E2eWorld) {
    load_audit(world).await;
    let valid = ["ecdsa-p256", "ed25519", "hmac-sha256"];
    for (i, line) in world.audit_lines.iter().enumerate() {
        let obj: serde_json::Value = serde_json::from_str(line).unwrap();
        let alg = obj["signature_algorithm"].as_str().unwrap_or("");
        assert!(
            valid.contains(&alg),
            "audit entry {i}: unknown algorithm '{alg}'"
        );
    }
}

#[then("the audit log contains no secrets")]
async fn no_secrets(world: &mut E2eWorld) {
    load_audit(world).await;
    let raw = world.audit_lines.join("\n");
    let patterns = [
        r"sk-[a-zA-Z0-9]{20,}",
        r"Bearer [a-zA-Z0-9._-]{20,}",
        r"api[_-]?key",
    ];
    for pat in &patterns {
        let re = regex::Regex::new(pat).unwrap();
        assert!(
            !re.is_match(&raw),
            "audit log matches secret pattern: {pat}"
        );
    }
}

#[then("the hash chain has no duplicates")]
async fn audit_chain_no_dupes(world: &mut E2eWorld) {
    load_audit(world).await;
    let hashes: Vec<String> = world
        .audit_lines
        .iter()
        .filter_map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).ok()?;
            v["previous_hash"].as_str().map(String::from)
        })
        .collect();

    let tail: Vec<&String> = hashes.iter().skip(1).collect();
    let unique: HashSet<&String> = tail.iter().copied().collect();
    assert_eq!(
        tail.len(),
        unique.len(),
        "duplicate previous_hash values in chain"
    );
}

#[then("all event_ids are unique")]
async fn audit_unique_ids(world: &mut E2eWorld) {
    load_audit(world).await;
    let ids: Vec<String> = world
        .audit_lines
        .iter()
        .filter_map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).ok()?;
            v["event_id"].as_str().map(String::from)
        })
        .collect();

    let unique: HashSet<&String> = ids.iter().collect();
    assert_eq!(ids.len(), unique.len(), "duplicate event_ids found");
}

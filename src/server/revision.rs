//! Configuration and policy revision stamping.
//!
//! A reload applies to the replica that received it and to no other. With one
//! daemon that is invisible; with several, two replicas can enforce two
//! different policies while both report healthy, and nothing in the response
//! says which one actually applied. That is the "mutable-per-pod configuration"
//! failure the HA story has to answer for.
//!
//! A revision is a content hash of the active configuration: same bytes, same
//! revision, on every replica. Exposing it on `/health` turns "are my replicas
//! consistent?" into a comparison anyone can make, and putting it in the audit
//! event makes *which policy applied* provable after the fact.
//!
//! # What a revision must guarantee
//!
//! 1. **Deterministic.** The same config must hash identically in every process
//!    and every run, or comparing replicas is meaningless. Plain
//!    `serde_json::to_vec` cannot provide this: [`std::collections::HashMap`]
//!    iterates in a per-process random order, so two replicas holding byte-identical
//!    config would disagree. This module canonicalizes by sorting every object's
//!    keys before hashing.
//! 2. **Secret-free.** `/health` is public (it stays reachable even when
//!    `/metrics` is token-gated), so the input to the hash has API keys and
//!    tokens redacted. Note this is defence in depth for the *input*: a SHA-256
//!    digest does not leak its preimage. It matters because a redacted secret
//!    also means rotating a key does not change the revision, which is the
//!    behaviour an operator expects — the *policy* did not change.
//! 3. **Sensitive to what matters.** Any change to routing, providers, models,
//!    budget, DLP, or policies must move the revision.

use serde_json::Value;
use sha2::{Digest, Sha256};

/// Keys whose values are redacted before hashing.
///
/// Matched case-insensitively against the JSON field name at any depth.
const SECRET_KEYS: &[&str] = &[
    "api_key",
    "bearer_token",
    "token",
    "secret",
    "password",
    "client_secret",
    "webhook_secret",
    "signing_key",
];

/// Placeholder substituted for a redacted value.
///
/// A single constant for every secret means rotating a key does not move the
/// revision: the deployed *policy* is unchanged, so the revision should be too.
const REDACTED: &str = "<redacted>";

/// Length of the short, human-comparable form of a revision.
///
/// 12 hex chars is 48 bits: ample to spot "these two replicas differ" by eye,
/// which is the only thing this value is used for.
const SHORT_LEN: usize = 12;

/// A content hash of one configuration snapshot.
///
/// Equality means the two snapshots are byte-identical after canonicalization
/// and secret redaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revision {
    full: String,
}

impl Revision {
    /// Full 64-char hex digest, prefixed with the algorithm.
    ///
    /// The prefix is deliberate: an unlabelled hex string invites a future
    /// change of algorithm that silently breaks every comparison.
    #[must_use]
    pub fn full(&self) -> &str {
        &self.full
    }

    /// First [`SHORT_LEN`] hex chars of the digest, for logs and eyeballing.
    #[must_use]
    pub fn short(&self) -> &str {
        let start = self.full.find(':').map_or(0, |i| i + 1);
        let hex = &self.full[start..];
        &hex[..SHORT_LEN.min(hex.len())]
    }
}

impl std::fmt::Display for Revision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.full)
    }
}

/// Field excluded from the config revision.
///
/// `expected_config_revision` is the operator's *assertion about* the revision,
/// so including it would make the value self-referential: writing the expected
/// revision into the config would change the revision it is compared against,
/// and no value could ever match.
const SELF_REFERENTIAL_KEY: &str = "expected_config_revision";

/// Computes the revision of a serializable configuration value.
///
/// Serializes, redacts secrets, canonicalizes key order, then hashes. A value
/// that cannot be serialized yields a well-known sentinel revision rather than
/// panicking: a health endpoint must not be able to take the process down, and
/// a sentinel that never matches a real revision fails visibly rather than
/// silently claiming consistency.
pub fn compute<T: serde::Serialize>(value: &T) -> Revision {
    let Ok(json) = serde_json::to_value(value) else {
        return Revision {
            full: "sha256:unavailable".to_string(),
        };
    };
    let redacted = redact(json);
    let canonical = canonical_bytes(&redacted);
    let digest = Sha256::digest(&canonical);
    Revision {
        full: format!("sha256:{}", hex::encode(digest)),
    }
}

/// Replaces every secret-looking value with [`REDACTED`], at any depth.
fn redact(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .filter(|(k, _)| k != SELF_REFERENTIAL_KEY)
                .map(|(k, v)| {
                    if is_secret_key(&k) {
                        (k, Value::String(REDACTED.to_string()))
                    } else {
                        (k, redact(v))
                    }
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.into_iter().map(redact).collect()),
        other => other,
    }
}

/// True when a JSON field name denotes a secret.
///
/// Substring rather than exact match so `anthropic_api_key` and
/// `metrics_bearer_token` are covered without enumerating every spelling.
fn is_secret_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    SECRET_KEYS.iter().any(|s| lower.contains(s))
}

/// Serializes `value` with every object's keys in sorted order.
///
/// This is the property that makes a revision comparable across replicas.
/// Arrays keep their order: in this config, order is meaningful (provider
/// priority, policy precedence), so reordering them is a real change and must
/// move the revision.
fn canonical_bytes(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            out.push(b'{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                // Serializing the key as a JSON string keeps quotes and escapes
                // unambiguous, so `a"b` and `a\"b` cannot collide.
                out.extend_from_slice(
                    serde_json::to_string(key)
                        .unwrap_or_else(|_| String::from("\"\""))
                        .as_bytes(),
                );
                out.push(b':');
                write_canonical(&map[*key], out);
            }
            out.push(b'}');
        }
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(item, out);
            }
            out.push(b']');
        }
        other => out.extend_from_slice(other.to_string().as_bytes()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole point: identical content must hash identically.
    #[test]
    fn same_content_same_revision() {
        let a = serde_json::json!({ "router": { "default": "x" }, "n": 1 });
        let b = serde_json::json!({ "router": { "default": "x" }, "n": 1 });
        assert_eq!(compute(&a), compute(&b));
    }

    /// Key order must not affect the revision.
    ///
    /// Without this, two replicas holding byte-identical config could report
    /// different revisions purely because of map iteration order, and the HA
    /// check would produce false alarms until nobody trusted it.
    #[test]
    fn key_order_does_not_change_the_revision() {
        let a = serde_json::json!({ "alpha": 1, "beta": 2, "gamma": { "x": 1, "y": 2 } });
        let b = serde_json::json!({ "gamma": { "y": 2, "x": 1 }, "beta": 2, "alpha": 1 });
        assert_eq!(
            compute(&a),
            compute(&b),
            "canonicalization must sort keys at every depth"
        );
    }

    /// Array order *must* change the revision: it encodes priority.
    #[test]
    fn array_order_changes_the_revision() {
        let a = serde_json::json!({ "mappings": [ { "p": 1 }, { "p": 2 } ] });
        let b = serde_json::json!({ "mappings": [ { "p": 2 }, { "p": 1 } ] });
        assert_ne!(
            compute(&a),
            compute(&b),
            "provider priority order is meaningful and must be part of the identity"
        );
    }

    /// A real config change must move the revision.
    #[test]
    fn content_change_moves_the_revision() {
        let a = serde_json::json!({ "router": { "default": "model-a" } });
        let b = serde_json::json!({ "router": { "default": "model-b" } });
        assert_ne!(compute(&a), compute(&b));
    }

    /// Rotating a secret must NOT move the revision.
    ///
    /// The revision answers "which policy is deployed". A rotated key is the
    /// same policy, and a revision that flapped on every rotation would train
    /// operators to ignore it.
    #[test]
    fn secret_rotation_does_not_move_the_revision() {
        let a = serde_json::json!({ "providers": [ { "name": "p", "api_key": "sk-old" } ] });
        let b = serde_json::json!({ "providers": [ { "name": "p", "api_key": "sk-new" } ] });
        assert_eq!(
            compute(&a),
            compute(&b),
            "rotating a credential does not change the deployed policy"
        );
    }

    /// Secrets must not reach the hash input.
    #[test]
    fn secrets_are_redacted_before_hashing() {
        let v = serde_json::json!({
            "server": { "api_key": "sk-super-secret" },
            "metrics": { "bearer_token": "tok-secret" },
            "nested": { "deep": { "client_secret": "cs-secret" } }
        });
        let canonical = String::from_utf8(canonical_bytes(&redact(v))).expect("utf8");
        assert!(!canonical.contains("sk-super-secret"));
        assert!(!canonical.contains("tok-secret"));
        assert!(!canonical.contains("cs-secret"));
        assert!(canonical.contains(REDACTED));
    }

    /// A changed *non-secret* value next to a secret must still move it.
    ///
    /// Guards the redaction from being too greedy and blinding the revision to
    /// real changes.
    #[test]
    fn redaction_does_not_blind_the_revision() {
        let a = serde_json::json!({ "providers": [ { "name": "p", "api_key": "k", "base_url": "https://a" } ] });
        let b = serde_json::json!({ "providers": [ { "name": "p", "api_key": "k", "base_url": "https://b" } ] });
        assert_ne!(compute(&a), compute(&b));
    }

    /// The short form is a prefix of the digest, not of the `sha256:` label.
    #[test]
    fn short_form_is_digest_prefix() {
        let rev = compute(&serde_json::json!({ "a": 1 }));
        assert_eq!(rev.short().len(), SHORT_LEN);
        assert!(rev.full().starts_with("sha256:"));
        assert!(rev.full()[7..].starts_with(rev.short()));
        assert!(
            !rev.short().contains(':'),
            "the short form must be digest, not label"
        );
    }

    /// The real-world source of non-determinism: a [`std::collections::HashMap`]
    /// field, which is what `ProviderConfig::headers` actually is.
    ///
    /// `serde_json::json!` preserves literal order, so the ordering tests above
    /// would pass even without canonicalization if a `HashMap` were the only
    /// hazard. This one builds the map twice with different insertion orders,
    /// which is exactly the shape two replicas see when they load the same TOML.
    #[test]
    fn hashmap_iteration_order_does_not_change_the_revision() {
        use std::collections::HashMap;

        #[derive(serde::Serialize)]
        struct WithHeaders {
            name: String,
            headers: HashMap<String, String>,
        }

        let pairs = [
            ("X-Alpha", "1"),
            ("X-Beta", "2"),
            ("X-Gamma", "3"),
            ("X-Delta", "4"),
            ("X-Epsilon", "5"),
            ("X-Zeta", "6"),
        ];

        let forward: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        let backward: HashMap<String, String> = pairs
            .iter()
            .rev()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();

        let a = WithHeaders {
            name: "p".to_string(),
            headers: forward,
        };
        let b = WithHeaders {
            name: "p".to_string(),
            headers: backward,
        };

        assert_eq!(
            compute(&a),
            compute(&b),
            "two replicas with the same headers must agree regardless of map order"
        );
    }

    /// The expected-revision field must not feed into the revision.
    ///
    /// Otherwise stamping a deployment with the revision it should be running
    /// would change that very revision, and the readiness check could never
    /// pass — a self-defeating contract.
    #[test]
    fn expected_revision_is_excluded_from_the_hash() {
        let bare = serde_json::json!({ "server": { "port": 13456 } });
        let stamped = serde_json::json!({
            "server": { "port": 13456, "expected_config_revision": "sha256:whatever" }
        });
        assert_eq!(
            compute(&bare),
            compute(&stamped),
            "the assertion about the revision cannot be part of the revision"
        );
    }

    /// Distinct string values must not collide through naive concatenation.
    #[test]
    fn adjacent_values_cannot_be_confused() {
        let a = serde_json::json!({ "x": "ab", "y": "c" });
        let b = serde_json::json!({ "x": "a", "y": "bc" });
        assert_ne!(
            compute(&a),
            compute(&b),
            "field boundaries must be preserved by the canonical encoding"
        );
    }
}

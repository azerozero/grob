//! Keyed authentication for policy tokens (decision tokens, HIT receipts).
//!
//! Policy tokens cross trust boundaries: decision tokens travel over the MCP
//! transport between a boss agent and grob, and HIT authorization receipts are
//! serialized to disk and posted over HTTP. A plain (unkeyed) hash provides no
//! protection there — an adversary who can edit a serialized token simply
//! recomputes the hash. These functions bind a token to a secret key via
//! HMAC-SHA256 so that only a holder of the key can produce a valid tag.
//!
//! The key is derived from `GROB_POLICY_SECRET` (falling back to the existing
//! `GROB_DLP_SECRET`) using the same HMAC-based key-derivation pattern as the
//! DLP name anonymizer. When neither is set a random per-process key is
//! generated: tokens stay unforgeable within a run but do not survive a
//! restart, and a warning is logged.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::OnceLock;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Process-wide derived policy signing key, computed once on first use.
static POLICY_KEY: OnceLock<[u8; 32]> = OnceLock::new();

/// Returns the process-wide policy signing key, deriving it on first call.
///
/// The key is derived once and cached for the lifetime of the process so that
/// every token shares a single, stable key without re-reading the environment.
fn policy_key() -> &'static [u8; 32] {
    POLICY_KEY.get_or_init(derive_key)
}

/// Derives a 32-byte signing key from the configured policy secret.
///
/// Prefers `GROB_POLICY_SECRET`, then `GROB_DLP_SECRET`, so deployments that
/// already provision a DLP secret keep stable tokens without extra config.
/// Falls back to a random per-process key when no secret is configured.
fn derive_key() -> [u8; 32] {
    // NOTE: Domain separator for the HMAC-based KDF. This is a public constant
    // for domain separation, not a secret; the secret comes from the env var.
    const KDF_DOMAIN: &[u8] = b"grob-policy-token-key-derivation-v1"; // CodeQL: hard-coded-cryptographic-value — intentional domain separator, not a secret.

    let secret = std::env::var("GROB_POLICY_SECRET")
        .or_else(|_| std::env::var("GROB_DLP_SECRET"))
        .ok();

    match secret {
        Some(secret) => {
            let mut mac = HmacSha256::new_from_slice(KDF_DOMAIN)
                .expect("invariant: KDF_DOMAIN is a fixed non-empty key, always valid for HMAC");
            mac.update(secret.as_bytes());
            mac.finalize().into_bytes().into()
        }
        None => {
            tracing::warn!(
                "policies: neither GROB_POLICY_SECRET nor GROB_DLP_SECRET is set; \
                 generating a random per-process policy signing key. Decision tokens \
                 and HIT receipts will not verify across restarts or across hosts. \
                 Set GROB_POLICY_SECRET to a shared secret for stable, cross-process tokens."
            );
            let mut key = [0u8; 32]; // CodeQL: hard-coded-cryptographic-value — zero-initialized buffer, immediately overwritten with CSPRNG output.
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut key);
            key
        }
    }
}

/// Computes a hex-encoded HMAC-SHA256 tag over `data` using the policy key.
///
/// The returned tag authenticates `data`: only a holder of the policy key can
/// produce a tag that [`verify_tag`] accepts, so a tampered token is rejected.
#[must_use]
pub fn compute_tag(data: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(policy_key())
        .expect("invariant: policy_key is [u8; 32], always valid for HMAC-SHA256");
    mac.update(data);
    hex::encode(mac.finalize().into_bytes())
}

/// Verifies a hex-encoded HMAC-SHA256 tag against `data` in constant time.
///
/// Returns `true` only when `tag_hex` is the valid tag for `data` under the
/// policy key. Comparison is constant-time to avoid leaking the tag via timing.
#[must_use]
pub fn verify_tag(data: &[u8], tag_hex: &str) -> bool {
    let Ok(provided) = hex::decode(tag_hex) else {
        return false;
    };
    let mut mac = HmacSha256::new_from_slice(policy_key())
        .expect("invariant: policy_key is [u8; 32], always valid for HMAC-SHA256");
    mac.update(data);
    let expected = mac.finalize().into_bytes();
    // Length check first; ct_eq over mismatched lengths would short-circuit anyway.
    if provided.len() != expected.len() {
        return false;
    }
    provided.ct_eq(&expected).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_roundtrips() {
        let tag = compute_tag(b"decision-token-fields");
        assert!(verify_tag(b"decision-token-fields", &tag));
    }

    #[test]
    fn tampered_data_fails() {
        let tag = compute_tag(b"mode=training");
        assert!(!verify_tag(b"mode=live", &tag));
    }

    #[test]
    fn garbage_tag_fails() {
        assert!(!verify_tag(b"data", "not-hex-zzzz"));
        assert!(!verify_tag(b"data", "deadbeef"));
    }

    #[test]
    fn tag_is_keyed_not_plain_sha256() {
        // A plain SHA-256 over the same bytes must NOT match the HMAC tag,
        // proving the tag depends on the secret key, not just the data.
        use sha2::Digest as _;
        let data = b"authorize";
        let plain = hex::encode(Sha256::digest(data));
        let keyed = compute_tag(data);
        assert_ne!(plain, keyed, "HMAC tag must differ from unkeyed SHA-256");
    }
}

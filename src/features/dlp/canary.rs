use std::sync::atomic::{AtomicU64, Ordering};

/// A generated canary token (syntactically valid fake).
#[derive(Debug, Clone)]
pub struct CanaryToken {
    pub fake: String,
    #[allow(dead_code)]
    pub canary_id: u64,
    #[allow(dead_code)]
    pub family: &'static str,
}

/// Generates deterministic canary tokens for detected secrets.
/// Each token has a unique monotonic ID for tracking.
pub struct CanaryGenerator {
    counter: AtomicU64,
}

impl Default for CanaryGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl CanaryGenerator {
    pub fn new() -> Self {
        Self {
            counter: AtomicU64::new(1),
        }
    }

    /// Generate a fake token by family and length (avoids needing a full SecretMatch).
    pub fn generate_for(&self, family: &str, matched_len: usize) -> CanaryToken {
        let id = self.counter.fetch_add(1, Ordering::Relaxed);

        let fake = match family {
            "github" => generate_github_canary(id, matched_len),
            "aws" => generate_aws_canary(id),
            "jwt" => generate_jwt_canary(id),
            _ => generate_generic_canary(id, matched_len),
        };

        CanaryToken {
            fake,
            canary_id: id,
            family: match family {
                "github" => "github",
                "aws" => "aws",
                "jwt" => "jwt",
                _ => "generic",
            },
        }
    }
}

/// GitHub PAT canary: uses `~` marker to ensure it does NOT re-match `[A-Za-z0-9]{36}` patterns.
fn generate_github_canary(id: u64, total_len: usize) -> String {
    let prefix = format!("ghp_~CANARY{:010}", id);
    let remaining = total_len.saturating_sub(prefix.len());
    format!("{}{}", prefix, "X".repeat(remaining))
}

/// AWS Access Key canary: uses `~` marker to avoid re-matching `[0-9A-Z]{16}` patterns.
fn generate_aws_canary(id: u64) -> String {
    format!("AKIA~CANARY{:010}", id)
}

/// JWT canary: minimal valid-looking JWT with canary kid.
fn generate_jwt_canary(id: u64) -> String {
    use base64::Engine;
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let header = format!(r#"{{"alg":"HS256","typ":"JWT","kid":"canary-{}"}}"#, id);
    let payload = format!(r#"{{"sub":"canary","iat":0,"canary_id":{}}}"#, id);

    let h = engine.encode(header.as_bytes());
    let p = engine.encode(payload.as_bytes());
    // Fake signature: 32 bytes of zeros
    let s = engine.encode([0u8; 32]);

    format!("{}.{}.{}", h, p, s)
}

/// Generic canary: uses `~` marker to avoid re-matching alnum-only patterns.
fn generate_generic_canary(id: u64, total_len: usize) -> String {
    let tag = format!("~CANARY{:06}", id);
    if total_len > tag.len() {
        format!("{}{}", tag, "X".repeat(total_len - tag.len()))
    } else {
        format!("~{}", "X".repeat(total_len.saturating_sub(1)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_github_canary() {
        let gen = CanaryGenerator::new();
        let canary = gen.generate_for("github", 40);
        assert!(canary.fake.starts_with("ghp_~CANARY"));
        assert_eq!(canary.fake.len(), 40);
        assert_eq!(canary.family, "github");
        assert!(canary.fake.contains('~'));
    }

    #[test]
    fn test_aws_canary() {
        let gen = CanaryGenerator::new();
        let canary = gen.generate_for("aws", 20);
        assert!(canary.fake.starts_with("AKIA~CANARY"));
        assert!(canary.fake.contains('~'));
    }

    #[test]
    fn test_jwt_canary() {
        use base64::Engine;
        let gen = CanaryGenerator::new();
        let canary = gen.generate_for("jwt", 100);
        let parts: Vec<&str> = canary.fake.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT should have 3 parts");
        let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[0])
            .unwrap();
        let header = String::from_utf8(header_bytes).unwrap();
        assert!(header.contains("canary"), "JWT header should contain canary kid");
    }

    #[test]
    fn test_generic_canary() {
        let gen = CanaryGenerator::new();
        let canary = gen.generate_for("generic", 32);
        assert_eq!(canary.fake.len(), 32);
        assert!(canary.fake.starts_with("~CANARY"));
        assert!(canary.fake.contains('~'));
    }

    #[test]
    fn test_monotonic_ids() {
        let gen = CanaryGenerator::new();
        let c1 = gen.generate_for("generic", 10);
        let c2 = gen.generate_for("generic", 10);
        assert!(c2.canary_id > c1.canary_id);
    }
}

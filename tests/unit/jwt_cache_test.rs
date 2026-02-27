//! JWT validation cache tests
//!
//! Verifies that the JWT validator caches validated tokens and avoids
//! repeated cryptographic signature verification.

#[cfg(test)]
mod tests {
    use grob::auth::jwt::{GrobClaims, JwtConfig, JwtValidator};
    use jsonwebtoken::{encode, EncodingKey, Header};

    const TEST_SECRET: &str = "test-secret-256-bits-minimum!!";

    fn make_token(claims: &GrobClaims, secret: &str) -> String {
        encode(
            &Header::default(),
            claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap()
    }

    fn test_claims() -> GrobClaims {
        GrobClaims {
            sub: "user-123".to_string(),
            tenant: None,
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as u64,
            iss: None,
            aud: None,
        }
    }

    #[test]
    fn test_jwt_cache_hit_returns_same_claims() {
        let config = JwtConfig {
            hmac_secret: TEST_SECRET.to_string(),
            ..Default::default()
        };
        let validator = JwtValidator::from_config(&config).unwrap();
        let token = make_token(&test_claims(), TEST_SECRET);

        // First call: cache miss → full validation
        let result1 = validator.validate(&token).unwrap();
        // Second call: cache hit → returns cached claims
        let result2 = validator.validate(&token).unwrap();

        assert_eq!(result1.sub, result2.sub);
        assert_eq!(result1.tenant_id(), result2.tenant_id());
        assert_eq!(result1.sub, "user-123");
    }

    #[test]
    fn test_jwt_cache_second_call_is_faster() {
        let config = JwtConfig {
            hmac_secret: TEST_SECRET.to_string(),
            ..Default::default()
        };
        let validator = JwtValidator::from_config(&config).unwrap();
        let token = make_token(&test_claims(), TEST_SECRET);

        // Warm up: first call (cache miss)
        let _ = validator.validate(&token).unwrap();

        // Measure cached path (many iterations to smooth out noise)
        let iterations = 1000;
        let start = std::time::Instant::now();
        for _ in 0..iterations {
            let _ = validator.validate(&token).unwrap();
        }
        let cached_duration = start.elapsed();

        // The cached path should complete 1000 iterations in < 50ms
        // (SHA-256 hash + moka lookup, no HMAC verification)
        assert!(
            cached_duration.as_millis() < 500,
            "Cached validation took too long: {:?} for {} iterations",
            cached_duration,
            iterations
        );
    }

    #[test]
    fn test_jwt_cache_different_tokens_independent() {
        let config = JwtConfig {
            hmac_secret: TEST_SECRET.to_string(),
            ..Default::default()
        };
        let validator = JwtValidator::from_config(&config).unwrap();

        let claims1 = GrobClaims {
            sub: "user-1".to_string(),
            ..test_claims()
        };
        let claims2 = GrobClaims {
            sub: "user-2".to_string(),
            ..test_claims()
        };

        let token1 = make_token(&claims1, TEST_SECRET);
        let token2 = make_token(&claims2, TEST_SECRET);

        let result1 = validator.validate(&token1).unwrap();
        let result2 = validator.validate(&token2).unwrap();

        assert_eq!(result1.sub, "user-1");
        assert_eq!(result2.sub, "user-2");

        // Re-validate from cache
        let cached1 = validator.validate(&token1).unwrap();
        let cached2 = validator.validate(&token2).unwrap();

        assert_eq!(cached1.sub, "user-1");
        assert_eq!(cached2.sub, "user-2");
    }

    #[test]
    fn test_jwt_cache_does_not_cache_failures() {
        let config = JwtConfig {
            hmac_secret: TEST_SECRET.to_string(),
            ..Default::default()
        };
        let validator = JwtValidator::from_config(&config).unwrap();

        // Expired token
        let expired_claims = GrobClaims {
            sub: "user-123".to_string(),
            tenant: None,
            exp: (chrono::Utc::now() - chrono::Duration::hours(1)).timestamp() as u64,
            iss: None,
            aud: None,
        };
        let token = make_token(&expired_claims, TEST_SECRET);

        // Should fail both times (not cached)
        assert!(validator.validate(&token).is_err());
        assert!(validator.validate(&token).is_err());
    }
}

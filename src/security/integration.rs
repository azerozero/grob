//! Integration layer for security features
//! Shows how to wire all security components together

use super::*;
use super::encryption::VaultKms;
use axum::{
    body::Body,
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::Response,
    Router,
};
use std::sync::Arc;
use tower_http::limit::RequestBodyLimitLayer;

/// Complete security configuration
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// Rate limiting
    pub rate_limit: RateLimitConfig,
    /// Security headers
    pub headers: SecurityHeadersConfig,
    /// CORS configuration
    pub cors: CorsConfig,
    /// Circuit breaker
    pub circuit_breaker: CircuitBreakerConfig,
    /// Body size limit (bytes)
    pub max_body_size: usize,
    /// KMS configuration
    pub kms: KmsConfig,
    /// Audit log directory
    pub audit_dir: std::path::PathBuf,
}

#[derive(Debug, Clone)]
pub enum KmsConfig {
    Vault { url: String, token: secrecy::SecretString, mount: String },
    Local { master_key: secrecy::SecretString },
    None,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            rate_limit: RateLimitConfig::strict(),
            headers: SecurityHeadersConfig::api_mode(),
            cors: CorsConfig::strict(),
            circuit_breaker: CircuitBreakerConfig::default(),
            max_body_size: 10 * 1024 * 1024, // 10MB
            kms: KmsConfig::None,
            audit_dir: std::path::PathBuf::from("/var/lib/grob/audit"),
        }
    }
}

/// Security layer that combines all features
pub struct SecurityLayer {
    pub rate_limiter: Arc<RateLimiter>,
    pub circuit_breakers: Arc<CircuitBreakerRegistry>,
    pub encryption: Option<Arc<EncryptionService>>,
    pub audit_log: Option<Arc<AuditLog>>,
    pub config: SecurityConfig,
}

impl SecurityLayer {
    /// Create new security layer with configuration
    pub fn new(config: SecurityConfig) -> anyhow::Result<Self> {
        let rate_limiter = Arc::new(RateLimiter::new(config.rate_limit.clone()));
        let circuit_breakers = Arc::new(CircuitBreakerRegistry::with_config(
            config.circuit_breaker.clone(),
        ));

        // Setup KMS and encryption
        let encryption = match &config.kms {
            KmsConfig::Vault { url, token, mount } => {
                let kms: Arc<dyn KmsProvider> = Arc::new(VaultKms::new(
                    url.clone(),
                    token.clone(),
                    mount.clone(),
                ));
                Some(Arc::new(EncryptionService::new(kms)))
            }
            KmsConfig::Local { master_key } => {
                let kms: Arc<dyn KmsProvider> = Arc::new(LocalKms::new(master_key.clone()));
                Some(Arc::new(EncryptionService::new(kms)))
            }
            KmsConfig::None => None,
        };

        // Setup audit log
        let audit_log = if config.audit_dir.as_os_str().is_empty() {
            None
        } else {
            let audit_config = audit_log::AuditConfig {
                log_dir: config.audit_dir.clone(),
                rotation_size: 100 * 1024 * 1024, // 100MB
                retention_days: 365,
                sign_key_path: Some(config.audit_dir.join("audit_key.pem")),
                encrypt: encryption.is_some(),
            };
            Some(Arc::new(AuditLog::new(audit_config)?))
        };

        Ok(Self {
            rate_limiter,
            circuit_breakers,
            encryption,
            audit_log,
            config,
        })
    }

    /// Create default security layer (production-ready)
    pub fn default_production(master_key: secrecy::SecretString) -> anyhow::Result<Self> {
        let mut config = SecurityConfig::default();
        config.kms = KmsConfig::Local { master_key };
        Self::new(config)
    }

    /// Apply security middleware to router
    pub fn apply_middleware(&self, router: Router) -> Router {
        // 1. Rate limiting (outer layer)
        let rate_limiter = Arc::clone(&self.rate_limiter);

        // 2. Request size limiting
        let size_limit = RequestBodyLimitLayer::new(self.config.max_body_size);

        // 3. Security headers (inner layer - applied last, executed first on response)
        let headers_config = self.config.headers.clone();

        // 4. CORS handling
        let _cors_config = self.config.cors.clone();

        router
            .layer(middleware::from_fn(
                move |req: Request<Body>, next: Next| {
                    let rate_limiter = rate_limiter.clone();
                    let headers_config = headers_config.clone();
                    async move {
                        // Apply rate limiting
                        let key = req
                            .headers()
                            .get("x-api-key")
                            .and_then(|h| h.to_str().ok())
                            .map(|k| RateLimitKey::Tenant(k.to_string()))
                            .or_else(|| {
                                req.extensions()
                                    .get::<std::net::SocketAddr>()
                                    .map(|addr| RateLimitKey::from_addr(*addr))
                            });

                        if let Some(key) = key {
                            let (allowed, _remaining, reset_after) = rate_limiter.check(&key).await;

                            if !allowed {
                                return Response::builder()
                                    .status(StatusCode::TOO_MANY_REQUESTS)
                                    .header("X-RateLimit-Limit", "100")
                                    .header("X-RateLimit-Remaining", "0")
                                    .header(
                                        "Retry-After",
                                        reset_after.map(|d| d.as_secs().to_string()).unwrap_or_default(),
                                    )
                                    .body(Body::from("Rate limit exceeded"))
                                    .unwrap();
                            }
                        }

                        let response = next.run(req).await;
                        apply_security_headers(response, &headers_config)
                    }
                },
            ))
            .layer(size_limit)
    }

    /// Execute provider call with circuit breaker
    pub async fn execute_with_circuit<F, Fut, T>(
        &self,
        provider: &str,
        f: F,
    ) -> Result<T, CircuitBreakerError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = anyhow::Result<T>>,
    {
        self.circuit_breakers.execute(provider, f).await
    }

    /// Log audit event
    pub async fn log_audit(&self, entry: AuditEntry) -> anyhow::Result<()> {
        if let Some(log) = &self.audit_log {
            log.write(entry)?;
        }
        Ok(())
    }

    /// Encrypt data for perimeter
    pub async fn encrypt(
        &self,
        data: &[u8],
        perimeter: Perimeter,
    ) -> anyhow::Result<EncryptedEnvelope> {
        match &self.encryption {
            Some(enc) => enc.encrypt(data, perimeter).await,
            None => Err(anyhow::anyhow!("Encryption not configured")),
        }
    }

    /// Decrypt data
    pub async fn decrypt(&self, envelope: &EncryptedEnvelope) -> anyhow::Result<Vec<u8>> {
        match &self.encryption {
            Some(enc) => enc.decrypt(envelope).await,
            None => Err(anyhow::anyhow!("Encryption not configured")),
        }
    }

    /// Get health status of all security components
    pub async fn health_check(&self) -> SecurityHealth {
        SecurityHealth {
            rate_limiter: true, // Always healthy if constructed
            circuit_breaker: true,
            encryption: self.encryption.is_some(),
            audit_log: self.audit_log.is_some(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SecurityHealth {
    pub rate_limiter: bool,
    pub circuit_breaker: bool,
    pub encryption: bool,
    pub audit_log: bool,
}

impl SecurityHealth {
    pub fn all_healthy(&self) -> bool {
        self.rate_limiter && self.circuit_breaker && self.encryption && self.audit_log
    }
}

/// Helper function to create production security stack
pub fn production_security_stack(
    master_key: secrecy::SecretString,
) -> anyhow::Result<SecurityLayer> {
    let config = SecurityConfig {
        rate_limit: RateLimitConfig::strict(),
        headers: SecurityHeadersConfig::strict(),
        cors: CorsConfig::strict(),
        circuit_breaker: CircuitBreakerConfig::critical(),
        max_body_size: 10 * 1024 * 1024,
        kms: KmsConfig::Local { master_key },
        audit_dir: std::path::PathBuf::from("/var/lib/grob/audit"),
    };

    SecurityLayer::new(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_security_layer_creation() {
        let master_key = secrecy::SecretString::new("test-key-32-bytes-long-for-testing!!".to_string());
        let mut config = SecurityConfig::default();
        config.kms = KmsConfig::Local { master_key };
        config.audit_dir = std::env::temp_dir().join("grob_test_audit_creation");
        let layer = SecurityLayer::new(config).unwrap();

        let health = layer.health_check().await;
        assert!(health.rate_limiter);
        assert!(health.encryption);
    }

    #[tokio::test]
    async fn test_circuit_breaker_execution() {
        let master_key = secrecy::SecretString::new("test-key-32-bytes-long-for-testing!!".to_string());
        let mut config = SecurityConfig::default();
        config.kms = KmsConfig::Local { master_key };
        config.audit_dir = std::env::temp_dir().join("grob_test_audit_circuit");
        let layer = SecurityLayer::new(config).unwrap();

        // Successful execution
        let result: Result<i32, _> = layer
            .execute_with_circuit("test-provider", || async { Ok(42) })
            .await;
        assert_eq!(result.unwrap(), 42);

        // Failed execution should trigger circuit breaker
        for _ in 0..5 {
            let result: Result<i32, _> = layer
                .execute_with_circuit("failing-provider", || async {
                    Err(anyhow::anyhow!("Simulated failure"))
                })
                .await;
            assert!(result.is_err());
        }

        // Circuit should be open now
        let state = layer.circuit_breakers.get_state("failing-provider").await;
        assert_eq!(state, Some(CircuitState::Open));
    }

    #[test]
    fn test_security_health() {
        let health = SecurityHealth {
            rate_limiter: true,
            circuit_breaker: true,
            encryption: true,
            audit_log: true,
        };
        assert!(health.all_healthy());

        let unhealthy = SecurityHealth {
            encryption: false,
            ..health
        };
        assert!(!unhealthy.all_healthy());
    }
}

//! Security headers middleware for Grob
//! Implements OWASP security headers recommendations
//! Conforms to HDS/PCI DSS/SecNumCloud requirements

use axum::{
    body::Body,
    http::{header, HeaderValue, Request, Response},
    middleware::Next,
};

/// Security headers configuration
#[derive(Debug, Clone)]
pub struct SecurityHeadersConfig {
    /// Enable Strict-Transport-Security (HSTS)
    pub hsts_enabled: bool,
    /// HSTS max-age in seconds (default: 1 year)
    pub hsts_max_age: u64,
    /// Include subdomains in HSTS
    pub hsts_include_subdomains: bool,
    /// Enable Content-Security-Policy
    pub csp_enabled: bool,
    /// CSP policy string
    pub csp_policy: String,
    /// X-Frame-Options (DENY, SAMEORIGIN, or ALLOW-FROM)
    pub frame_options: FrameOption,
    /// X-Content-Type-Options (nosniff)
    pub content_type_options: bool,
    /// Referrer-Policy
    pub referrer_policy: ReferrerPolicy,
    /// Permissions-Policy (Feature-Policy)
    pub permissions_policy: Option<String>,
    /// X-XSS-Protection (legacy, mostly ignored by modern browsers)
    pub xss_protection: bool,
}

#[derive(Debug, Clone)]
pub enum FrameOption {
    Deny,
    SameOrigin,
    AllowFrom(String),
}

#[derive(Debug, Clone)]
pub enum ReferrerPolicy {
    NoReferrer,
    NoReferrerWhenDowngrade,
    Origin,
    OriginWhenCrossOrigin,
    SameOrigin,
    StrictOrigin,
    StrictOriginWhenCrossOrigin,
    UnsafeUrl,
}

impl Default for SecurityHeadersConfig {
    fn default() -> Self {
        Self {
            hsts_enabled: true,
            hsts_max_age: 31536000, // 1 year
            hsts_include_subdomains: true,
            csp_enabled: true,
            csp_policy: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self' https:; frame-ancestors 'none'; base-uri 'self'; form-action 'self';".to_string(),
            frame_options: FrameOption::Deny,
            content_type_options: true,
            referrer_policy: ReferrerPolicy::StrictOriginWhenCrossOrigin,
            permissions_policy: Some("accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()".to_string()),
            xss_protection: false, // Deprecated, CSP is preferred
        }
    }
}

/// Security headers for API mode (minimal, no CSP needed for API)
impl SecurityHeadersConfig {
    pub fn api_mode() -> Self {
        Self {
            hsts_enabled: true,
            hsts_max_age: 31536000,
            hsts_include_subdomains: true,
            csp_enabled: false, // Not needed for API
            csp_policy: String::new(),
            frame_options: FrameOption::Deny,
            content_type_options: true,
            referrer_policy: ReferrerPolicy::NoReferrer,
            permissions_policy: Some("accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()".to_string()),
            xss_protection: false,
        }
    }

    /// Strict mode for HDS/PCI/SecNumCloud
    pub fn strict() -> Self {
        Self {
            hsts_enabled: true,
            hsts_max_age: 63072000, // 2 years
            hsts_include_subdomains: true,
            csp_enabled: true,
            csp_policy: "default-src 'none'; script-src 'none'; style-src 'none'; img-src 'none'; font-src 'none'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; upgrade-insecure-requests;".to_string(),
            frame_options: FrameOption::Deny,
            content_type_options: true,
            referrer_policy: ReferrerPolicy::NoReferrer,
            permissions_policy: Some("accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), interest-cohort=()".to_string()),
            xss_protection: false,
        }
    }
}

/// Apply security headers to response
pub fn apply_security_headers<B>(
    mut response: Response<B>,
    config: &SecurityHeadersConfig,
) -> Response<B> {
    let headers = response.headers_mut();

    // HSTS (HTTPS only)
    if config.hsts_enabled {
        let hsts_value = if config.hsts_include_subdomains {
            format!("max-age={}; includeSubDomains", config.hsts_max_age)
        } else {
            format!("max-age={}", config.hsts_max_age)
        };
        if let Ok(val) = HeaderValue::from_str(&hsts_value) {
            headers.insert(header::STRICT_TRANSPORT_SECURITY, val);
        }
    }

    // Content-Security-Policy
    if config.csp_enabled && !config.csp_policy.is_empty() {
        if let Ok(val) = HeaderValue::from_str(&config.csp_policy) {
            headers.insert("content-security-policy", val);
        }
    }

    // X-Frame-Options
    let frame_value = match &config.frame_options {
        FrameOption::Deny => "DENY",
        FrameOption::SameOrigin => "SAMEORIGIN",
        FrameOption::AllowFrom(url) => {
            if let Ok(val) = HeaderValue::from_str(&format!("ALLOW-FROM {}", url)) {
                headers.insert("x-frame-options", val);
            }
            return response;
        }
    };
    if let Ok(val) = HeaderValue::from_str(frame_value) {
        headers.insert("x-frame-options", val);
    }

    // X-Content-Type-Options
    if config.content_type_options {
        if let Ok(val) = HeaderValue::from_str("nosniff") {
            headers.insert("x-content-type-options", val);
        }
    }

    // Referrer-Policy
    let referrer_value = match config.referrer_policy {
        ReferrerPolicy::NoReferrer => "no-referrer",
        ReferrerPolicy::NoReferrerWhenDowngrade => "no-referrer-when-downgrade",
        ReferrerPolicy::Origin => "origin",
        ReferrerPolicy::OriginWhenCrossOrigin => "origin-when-cross-origin",
        ReferrerPolicy::SameOrigin => "same-origin",
        ReferrerPolicy::StrictOrigin => "strict-origin",
        ReferrerPolicy::StrictOriginWhenCrossOrigin => "strict-origin-when-cross-origin",
        ReferrerPolicy::UnsafeUrl => "unsafe-url",
    };
    if let Ok(val) = HeaderValue::from_str(referrer_value) {
        headers.insert("referrer-policy", val);
    }

    // Permissions-Policy (Feature-Policy)
    if let Some(policy) = &config.permissions_policy {
        if let Ok(val) = HeaderValue::from_str(policy) {
            headers.insert("permissions-policy", val);
        }
    }

    // X-XSS-Protection (legacy, mostly ignored)
    if config.xss_protection {
        if let Ok(val) = HeaderValue::from_str("1; mode=block") {
            headers.insert("x-xss-protection", val);
        }
    }

    // Cache-Control for sensitive endpoints
    // Don't cache API responses
    if let Ok(val) = HeaderValue::from_str("no-store, no-cache, must-revalidate, private") {
        headers.insert(header::CACHE_CONTROL, val);
    }

    response
}

/// Axum middleware for security headers
pub async fn security_headers_middleware(
    req: Request<Body>,
    next: Next,
    config: SecurityHeadersConfig,
) -> Response<Body> {
    let response = next.run(req).await;
    apply_security_headers(response, &config)
}

/// CORS configuration for API
#[derive(Debug, Clone)]
pub struct CorsConfig {
    /// Allowed origins (None = wildcard - NOT recommended for production)
    pub allowed_origins: Option<Vec<String>>,
    /// Allowed methods
    pub allowed_methods: Vec<String>,
    /// Allowed headers
    pub allowed_headers: Vec<String>,
    /// Allow credentials
    pub allow_credentials: bool,
    /// Max age for preflight
    pub max_age: u64,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allowed_origins: None, // No CORS by default
            allowed_methods: vec!["GET".to_string(), "POST".to_string(), "OPTIONS".to_string()],
            allowed_headers: vec![
                "authorization".to_string(),
                "content-type".to_string(),
                "x-api-key".to_string(),
                "x-request-id".to_string(),
            ],
            allow_credentials: false,
            max_age: 86400, // 24 hours
        }
    }
}

impl CorsConfig {
    /// Strict mode - no CORS (recommended for internal APIs)
    pub fn strict() -> Self {
        Self {
            allowed_origins: None,
            allowed_methods: vec![],
            allowed_headers: vec![],
            allow_credentials: false,
            max_age: 0,
        }
    }

    /// Validate origin against allowlist
    pub fn is_origin_allowed(&self, origin: &str) -> bool {
        match &self.allowed_origins {
            None => false,
            Some(origins) => origins.iter().any(|o| o == origin || o == "*"),
        }
    }
}

/// Build CORS headers for response
pub fn build_cors_headers(origin: &str, config: &CorsConfig) -> Vec<(String, String)> {
    let mut headers = Vec::new();

    if config.is_origin_allowed(origin) {
        headers.push(("Access-Control-Allow-Origin".to_string(), origin.to_string()));

        if config.allow_credentials {
            headers.push(("Access-Control-Allow-Credentials".to_string(), "true".to_string()));
        }

        if !config.allowed_methods.is_empty() {
            headers.push((
                "Access-Control-Allow-Methods".to_string(),
                config.allowed_methods.join(", "),
            ));
        }

        if !config.allowed_headers.is_empty() {
            headers.push((
                "Access-Control-Allow-Headers".to_string(),
                config.allowed_headers.join(", "),
            ));
        }

        headers.push((
            "Access-Control-Max-Age".to_string(),
            config.max_age.to_string(),
        ));
    }

    headers
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::StatusCode;

    fn create_test_response() -> Response<Body> {
        Response::builder().status(StatusCode::OK).body(Body::empty()).unwrap()
    }

    #[test]
    fn test_security_headers_default() {
        let config = SecurityHeadersConfig::default();
        let response = create_test_response();
        let response = apply_security_headers(response, &config);

        let headers = response.headers();
        assert!(headers.contains_key("strict-transport-security"));
        assert!(headers.contains_key("content-security-policy"));
        assert!(headers.contains_key("x-frame-options"));
        assert!(headers.contains_key("x-content-type-options"));
        assert!(headers.contains_key("referrer-policy"));
        assert!(headers.contains_key("permissions-policy"));
    }

    #[test]
    fn test_security_headers_api_mode() {
        let config = SecurityHeadersConfig::api_mode();
        let response = create_test_response();
        let response = apply_security_headers(response, &config);

        let headers = response.headers();
        assert!(headers.contains_key("strict-transport-security"));
        assert!(!headers.contains_key("content-security-policy")); // Not in API mode
    }

    #[test]
    fn test_security_headers_strict() {
        let config = SecurityHeadersConfig::strict();
        assert!(config.csp_policy.contains("default-src 'none'"));

        let response = create_test_response();
        let response = apply_security_headers(response, &config);

        let headers = response.headers();
        let hsts = headers.get("strict-transport-security").unwrap().to_str().unwrap();
        assert!(hsts.contains("63072000")); // 2 years
    }

    #[test]
    fn test_frame_options() {
        let mut config = SecurityHeadersConfig::default();
        config.frame_options = FrameOption::SameOrigin;

        let response = create_test_response();
        let response = apply_security_headers(response, &config);

        let headers = response.headers();
        let frame = headers.get("x-frame-options").unwrap().to_str().unwrap();
        assert_eq!(frame, "SAMEORIGIN");
    }

    #[test]
    fn test_cors_config() {
        let config = CorsConfig::default();
        assert!(!config.is_origin_allowed("https://example.com"));

        let config = CorsConfig {
            allowed_origins: Some(vec!["https://example.com".to_string()]),
            ..Default::default()
        };
        assert!(config.is_origin_allowed("https://example.com"));
        assert!(!config.is_origin_allowed("https://evil.com"));
    }

    #[test]
    fn test_cors_wildcard() {
        let config = CorsConfig {
            allowed_origins: Some(vec!["*".to_string()]),
            ..Default::default()
        };
        assert!(config.is_origin_allowed("https://any.com"));
    }

    #[test]
    fn test_cors_headers() {
        let config = CorsConfig {
            allowed_origins: Some(vec!["https://example.com".to_string()]),
            allowed_methods: vec!["GET".to_string(), "POST".to_string()],
            allow_credentials: true,
            ..Default::default()
        };

        let headers = build_cors_headers("https://example.com", &config);
        assert!(headers.iter().any(|(k, _)| k == "Access-Control-Allow-Origin"));
        assert!(headers.iter().any(|(k, _)| k == "Access-Control-Allow-Credentials"));
    }

    #[test]
    fn test_referrer_policies() {
        let policies = vec![
            (ReferrerPolicy::NoReferrer, "no-referrer"),
            (ReferrerPolicy::StrictOriginWhenCrossOrigin, "strict-origin-when-cross-origin"),
        ];

        for (policy, expected) in policies {
            let mut config = SecurityHeadersConfig::default();
            config.referrer_policy = policy;

            let response = create_test_response();
            let response = apply_security_headers(response, &config);

            let headers = response.headers();
            let actual = headers.get("referrer-policy").unwrap().to_str().unwrap();
            assert_eq!(actual, expected);
        }
    }
}

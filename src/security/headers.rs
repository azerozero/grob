//! Security headers middleware for Grob
//! Implements OWASP security headers recommendations
//! Conforms to HDS/PCI DSS/SecNumCloud requirements

use axum::{
    http::{header, HeaderValue, Response},
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
}

#[derive(Debug, Clone)]
pub enum ReferrerPolicy {
    NoReferrer,
    StrictOriginWhenCrossOrigin,
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
        ReferrerPolicy::StrictOriginWhenCrossOrigin => "strict-origin-when-cross-origin",
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

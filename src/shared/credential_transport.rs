//! Transport constraints for requests carrying provider credentials.

use reqwest::{redirect::Policy, Client, ClientBuilder, Url};

/// Recognizes loopback hosts without accepting lookalike domains.
pub(crate) fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain("localhost")) => true,
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        _ => false,
    }
}

/// Validates HTTPS endpoints, allowing HTTP only for local integrations.
///
/// Errors deliberately omit the supplied URL, which may itself contain secrets.
pub(crate) fn validate_endpoint(endpoint: &str) -> Result<Url, &'static str> {
    let url = Url::parse(endpoint).map_err(|_| "Invalid credential endpoint URL")?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err("Credential endpoints must not contain URL userinfo");
    }
    match url.scheme() {
        "https" => Ok(url),
        "http" if is_loopback(&url) => Ok(url),
        _ => Err("Credential endpoints require HTTPS outside loopback"),
    }
}

/// Prevents redirects from forwarding credentials to another endpoint or HTTP.
pub(crate) fn client_builder() -> ClientBuilder {
    Client::builder().redirect(Policy::none())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permits_https_and_loopback_http() {
        for endpoint in [
            "https://api.example.com/token",
            "http://localhost:1234/token",
            "http://127.0.0.1:1234/token",
            "http://[::1]:1234/token",
        ] {
            assert!(validate_endpoint(endpoint).is_ok(), "{endpoint}");
        }
    }

    #[test]
    fn rejects_cleartext_and_loopback_lookalikes_without_echoing_secrets() {
        for endpoint in [
            "http://example.com/token?key=private-value",
            "http://localhost.example.com/token",
            "http://127.0.0.1.example.com/token",
            "http://localhost@evil.example/token",
            "https://user:private-value@example.com/token",
            "file:///tmp/token",
            "not a url: private-value",
        ] {
            let error = validate_endpoint(endpoint).unwrap_err();
            assert!(!error.contains("private-value"));
        }
    }

    #[tokio::test]
    async fn does_not_forward_credentials_on_redirect() {
        let mut source = mockito::Server::new_async().await;
        let mut destination = mockito::Server::new_async().await;
        let target = destination
            .mock("POST", "/token")
            .expect(0)
            .create_async()
            .await;
        let redirect = source
            .mock("POST", "/token")
            .with_status(307)
            .with_header("location", &format!("{}/token", destination.url()))
            .create_async()
            .await;
        let response = client_builder()
            .build()
            .unwrap()
            .post(format!("{}/token", source.url()))
            .header("x-goog-api-key", "synthetic-key")
            .body("refresh_token=synthetic-token")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::TEMPORARY_REDIRECT);
        redirect.assert_async().await;
        target.assert_async().await;
    }
}

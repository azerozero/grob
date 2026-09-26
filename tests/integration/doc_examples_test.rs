//! Checks published examples against the real schema without resolving secrets or calling providers.

use grob::cli::AppConfig;
use std::path::Path;

mod markdown;
mod syntax;

const CONFIGURATION: &str = "docs/reference/configuration.md";
const OPERATIONS: &str = "docs/reference/operations.md";
const BASE: &str = r#"
[router]
default = "example"
[[providers]]
name = "example"
provider_type = "openai"
api_key = "synthetic-never-sent"
models = []
[[models]]
name = "example"
[[models.mappings]]
provider = "example"
actual_model = "example"
priority = 1
"#;

fn read_doc(path: &str) -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
        .unwrap_or_else(|error| panic!("{path}: {error}"))
        .replace("\r\n", "\n")
}

fn toml_blocks(markdown: &str, label: &str) -> Vec<String> {
    let blocks: Vec<_> = markdown::blocks(markdown)
        .unwrap_or_else(|error| panic!("{label}: {error}"))
        .into_iter()
        .filter(|block| block.language == "toml")
        .map(|block| block.source)
        .collect();
    assert!(!blocks.is_empty(), "{label}: no TOML examples found");
    blocks
}

fn section_example(path: &str, heading: &str) -> String {
    let markdown = read_doc(path);
    let blocks: Vec<_> = markdown::blocks(&markdown)
        .unwrap_or_else(|error| panic!("{path}: {error}"))
        .into_iter()
        .filter(|block| block.heading == heading && block.language == "toml")
        .collect();
    assert_eq!(
        blocks.len(),
        1,
        "{path}: {heading} must have one TOML example"
    );
    blocks[0].source.clone()
}

fn parse_config(content: &str, label: &str) -> AppConfig {
    // Keep environment placeholders literal, as in the existing full-example tests.
    // Startup would resolve credentials; these schema checks must never read them.
    let config: AppConfig =
        toml::from_str(content).unwrap_or_else(|error| panic!("{label}: {error}"));
    config
        .validate()
        .unwrap_or_else(|error| panic!("{label}: {error}"));
    config
}

fn example_config(path: &str, heading: &str) -> AppConfig {
    parse_config(
        &format!("{BASE}\n{}", section_example(path, heading)),
        &format!("{path}: {heading}"),
    )
}

#[test]
fn jwt_example_activates_authentication() {
    let config = example_config(CONFIGURATION, "## Authentication (JWT)");
    assert_eq!(config.auth.mode, "jwt");
    assert_eq!(
        config.auth.jwt.jwks_url,
        "https://example.com/.well-known/jwks.json"
    );
    assert_eq!(
        config.auth.jwt.issuer.as_deref(),
        Some("https://example.com")
    );
    assert_eq!(config.auth.jwt.audience.as_deref(), Some("grob"));
}

#[test]
fn tap_example_sets_destination_and_payload_policy() {
    let config = example_config(CONFIGURATION, "## Tap (Webhook Events)");
    assert_eq!(config.tap.webhook_url, "https://hooks.example.com/grob");
    assert!(!config.tap.enabled, "the reference leaves delivery opt-in");
    assert!(!config.tap.include_request);
    assert_eq!(config.tap.buffer_size, 256);
    assert_eq!(config.tap.timeout_ms, 5000);
}

#[test]
fn tls_example_enables_manual_certificates() {
    let config = example_config(OPERATIONS, "### Manual TLS");
    assert!(config.server.tls.enabled);
    assert_eq!(config.server.tls.cert_path, "/etc/ssl/certs/grob.pem");
    assert_eq!(config.server.tls.key_path, "/etc/ssl/private/grob-key.pem");
}

#[test]
fn acme_example_enables_provisioning() {
    let config = example_config(OPERATIONS, "### ACME (Let's Encrypt)");
    assert!(config.server.tls.enabled);
    assert!(config.server.tls.acme.enabled);
    assert_eq!(config.server.tls.acme.domains, ["grob.example.com"]);
    assert_eq!(config.server.tls.acme.contacts, ["admin@example.com"]);
    assert!(!config.server.tls.acme.staging);
}

#[test]
fn timeout_example_sets_request_and_connect_limits() {
    let source = section_example(OPERATIONS, "## Timeouts");
    assert!(
        has_timeout_fields(&source),
        "timeout table and both keys must be explicit"
    );
    let config = example_config(OPERATIONS, "## Timeouts");
    assert_eq!(config.server.timeouts.api_timeout_ms, 600_000);
    assert_eq!(config.server.timeouts.connect_timeout_ms, 10_000);
}

fn has_timeout_fields(source: &str) -> bool {
    let value: toml::Value = toml::from_str(source).expect("valid TOML");
    ["api_timeout_ms", "connect_timeout_ms"].iter().all(|key| {
        value
            .get("server")
            .and_then(|v| v.get("timeouts"))
            .and_then(|v| v.get(key))
            .and_then(toml::Value::as_integer)
            .is_some()
    })
}

#[test]
fn timeout_examples_cannot_fall_back_to_defaults() {
    let source = section_example(OPERATIONS, "## Timeouts");
    assert!(!has_timeout_fields(
        &source.replace("[server.timeouts]", "[server.timeout]")
    ));
    assert!(!has_timeout_fields(
        &source.replace("api_timeout_ms", "api_timout_ms")
    ));
}

#[test]
fn dlp_examples_activate_both_directions() {
    for (path, heading) in [
        (CONFIGURATION, "## DLP (Data Loss Prevention)"),
        ("docs/how-to/configure.md", "## Enable DLP scanning"),
        (
            "README.md",
            "## DLP -- secrets screened before they reach the provider",
        ),
    ] {
        let config = example_config(path, heading);
        assert!(config.dlp.enabled, "{path}: DLP disabled");
        assert!(config.dlp.scan_input, "{path}: input scanning disabled");
        assert!(config.dlp.scan_output, "{path}: output scanning disabled");
    }
}

#[test]
fn readme_example_is_a_complete_configuration() {
    parse_config(
        &section_example("README.md", "## Configuration"),
        "README.md",
    );
}

#[test]
fn provider_fragments_match_the_schema() {
    let path = "docs/how-to/providers.md";
    let markdown = read_doc(path);
    for (index, block) in toml_blocks(&markdown, path).iter().enumerate() {
        // Fragments intentionally omit routing or referenced providers. Check
        // their real types, leaving cross-reference validation to full configs.
        let content = format!("[router]\ndefault = \"example\"\n{block}");
        let config: AppConfig = toml::from_str(&content)
            .unwrap_or_else(|error| panic!("{path}: TOML block {}: {error}", index + 1));
        assert!(
            !config.providers.is_empty() || !config.models.is_empty(),
            "{path}: block {} has neither providers nor models",
            index + 1
        );
    }
}

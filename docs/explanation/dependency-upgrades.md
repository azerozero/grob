# Dependency upgrades

The September 2026 dependency refresh updates the Rust HTTP, configuration,
cryptography, metrics, compression and test libraries together. The lockfile
also includes current compatible transitive dependencies. Production and demo
container builds use Rust 1.98 on Alpine 3.24.

## Compatibility checks

Persisted credentials keep the same AES-256-GCM envelope and key file format.
Tests decrypt fixed ciphertext produced with aes-gcm 0.10, verify signatures
produced with p256 0.13 and ed25519-dalek 2, and check a fixed audit-chain hash.
Existing storage, JWT, OAuth, routing, streaming and configuration tests also
exercise the new libraries.

Reqwest 0.13 uses rustls with the platform certificate verifier. Standalone
installs use the operating system trust store; scratch containers retain the
CA bundle copied from the build image. OAuth form bodies and URL query encoding
are explicitly enabled. Credential-bearing clients still reject insecure
remote endpoints and disable redirects.

## OpenTelemetry compatibility

The SDK and exporters use OpenTelemetry 0.33 together with
tracing-opentelemetry 0.34, released on 23 September 2026. The previous bridge
release (0.33) required SDK 0.32, so upgrading only the SDK produced incompatible
Context and Tracer types. The coordinated upgrade preserves all three signals:
traces, logs and metrics.

Renovate groups the SDK, exporters and tracing bridge together for review.
Validate this group with all-features tests and Clippy before merging.

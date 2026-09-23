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

## OpenTelemetry compatibility hold

The latest published tracing-opentelemetry 0.33 requires opentelemetry 0.32.
Moving the SDK and exporters to 0.33 alone creates incompatible Context and
Tracer types, so the complete OpenTelemetry stack stays on 0.32 for now.
Renovate groups these libraries separately and requests dashboard approval;
updates remain visible instead of being excluded by a version filter.

Approve that group when a released tracing-opentelemetry supports the proposed
SDK version, then run the all-features tests and Clippy, including the OTLP
trace, log and metrics paths.

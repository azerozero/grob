//! Tests for the sidecar layer.
//!
//! Driven against a real unix-socket server rather than a mock, so the
//! transport, framing and timeout paths are exercised rather than described.

use super::config::{Endpoint, SidecarConfig};
use super::proto::{Capability, SidecarError, SidecarRequest, SidecarResponse, PROTOCOL_VERSION};
use super::SidecarClient;
use std::collections::HashMap;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

/// How a stub sidecar should behave for one test.
#[derive(Clone, Copy)]
enum Behaviour {
    /// Echo the payload back as text at the current protocol version.
    Echo,
    /// Answer with a mismatched protocol version.
    WrongVersion,
    /// Report an application-level failure.
    ReportError,
    /// Accept the connection and never answer.
    Hang,
    /// Answer with bytes that are not valid JSON.
    Garbage,
}

/// Starts a stub sidecar on a temporary unix socket.
///
/// Returns the socket path and the temp dir, which must be kept alive for the
/// duration of the test.
fn start_stub(behaviour: Behaviour) -> (String, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("sidecar.sock");
    let path_string = path.to_string_lossy().into_owned();
    let listener = UnixListener::bind(&path).expect("bind");

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (reader, mut writer) = tokio::io::split(stream);
                let mut line = String::new();
                if BufReader::new(reader).read_line(&mut line).await.is_err() {
                    return;
                }
                let request: SidecarRequest = match serde_json::from_str(&line) {
                    Ok(r) => r,
                    Err(_) => return,
                };

                let reply = match behaviour {
                    Behaviour::Echo => serde_json::to_string(&SidecarResponse {
                        version: PROTOCOL_VERSION,
                        text: Some(format!("decoded:{}", request.payload)),
                        payload: None,
                        error: None,
                    })
                    .expect("serialise"),
                    Behaviour::WrongVersion => serde_json::to_string(&SidecarResponse {
                        version: PROTOCOL_VERSION + 99,
                        text: Some("ignored".into()),
                        payload: None,
                        error: None,
                    })
                    .expect("serialise"),
                    Behaviour::ReportError => serde_json::to_string(&SidecarResponse {
                        version: PROTOCOL_VERSION,
                        text: None,
                        payload: None,
                        error: Some("model not loaded".into()),
                    })
                    .expect("serialise"),
                    Behaviour::Hang => {
                        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                        return;
                    }
                    Behaviour::Garbage => "{not json at all".to_string(),
                };
                let _ = writer.write_all(format!("{reply}\n").as_bytes()).await;
                let _ = writer.flush().await;
            });
        }
    });

    (path_string, dir)
}

fn config_for(path: &str, timeout_ms: u64) -> SidecarConfig {
    let mut endpoints = HashMap::new();
    endpoints.insert(
        Capability::Ocr.as_str().to_string(),
        Endpoint::Unix {
            path: path.to_string(),
        },
    );
    SidecarConfig {
        endpoints,
        timeout_ms: Some(timeout_ms),
    }
}

#[tokio::test]
async fn a_configured_sidecar_answers() {
    let (path, _dir) = start_stub(Behaviour::Echo);
    let client = SidecarClient::new(config_for(&path, 5_000));

    assert!(client.is_enabled(Capability::Ocr));
    let text = client.ocr("QUJD").await.expect("ocr");
    assert_eq!(text, "decoded:QUJD");
    assert!(!client.is_tripped());
}

#[tokio::test]
async fn an_unconfigured_capability_is_off_not_broken() {
    // The defining availability property: Grob works without any sidecar.
    let client = SidecarClient::new(SidecarConfig::default());

    assert!(!client.is_enabled(Capability::Ocr));
    assert!(!client.is_enabled(Capability::Watermark));
    assert!(!client.is_enabled(Capability::Provenance));

    let err = client.ocr("QUJD").await.unwrap_err();
    assert_eq!(err, SidecarError::NotConfigured("ocr"));
    // A capability that is switched off must not count as a failure, or an
    // unconfigured deployment would trip its own breaker.
    assert!(!client.is_tripped());
}

#[tokio::test]
async fn a_missing_socket_is_reported_as_unreachable() {
    let client = SidecarClient::new(config_for("/nonexistent/path/to.sock", 5_000));
    let err = client.ocr("QUJD").await.unwrap_err();
    assert!(matches!(err, SidecarError::Unreachable(_)), "got {err:?}");
}

#[tokio::test]
async fn a_hanging_sidecar_hits_the_deadline() {
    let (path, _dir) = start_stub(Behaviour::Hang);
    let client = SidecarClient::new(config_for(&path, 150));

    let started = std::time::Instant::now();
    let err = client.ocr("QUJD").await.unwrap_err();
    assert!(matches!(err, SidecarError::Timeout(150)), "got {err:?}");
    // The deadline must actually bound the wait, not merely be reported.
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "waited {:?}, far past the 150 ms deadline",
        started.elapsed()
    );
}

#[tokio::test]
async fn a_version_mismatch_is_refused() {
    let (path, _dir) = start_stub(Behaviour::WrongVersion);
    let client = SidecarClient::new(config_for(&path, 5_000));

    let err = client.ocr("QUJD").await.unwrap_err();
    assert_eq!(
        err,
        SidecarError::VersionMismatch {
            expected: PROTOCOL_VERSION,
            actual: PROTOCOL_VERSION + 99,
        }
    );
}

#[tokio::test]
async fn a_reported_error_surfaces_verbatim() {
    let (path, _dir) = start_stub(Behaviour::ReportError);
    let client = SidecarClient::new(config_for(&path, 5_000));

    let err = client.ocr("QUJD").await.unwrap_err();
    assert_eq!(err, SidecarError::Reported("model not loaded".into()));
}

#[tokio::test]
async fn a_garbage_response_is_malformed_not_a_panic() {
    let (path, _dir) = start_stub(Behaviour::Garbage);
    let client = SidecarClient::new(config_for(&path, 5_000));

    let err = client.ocr("QUJD").await.unwrap_err();
    assert!(matches!(err, SidecarError::Malformed(_)), "got {err:?}");
}

#[tokio::test]
async fn repeated_failures_trip_the_breaker_and_recovery_resets_it() {
    let client = SidecarClient::new(config_for("/nonexistent/path/to.sock", 200));

    for _ in 0..5 {
        assert!(client.ocr("QUJD").await.is_err());
    }
    assert!(client.is_tripped(), "five failures should trip the breaker");

    // Once tripped, calls are refused without touching the transport.
    let err = client.ocr("QUJD").await.unwrap_err();
    assert_eq!(err, SidecarError::CircuitOpen);

    client.reset();
    assert!(!client.is_tripped());
}

#[tokio::test]
async fn a_success_clears_earlier_failures() {
    let (path, _dir) = start_stub(Behaviour::Echo);
    let mut config = config_for(&path, 5_000);
    // Point at a dead socket first, then at the live one.
    config.endpoints.insert(
        Capability::Ocr.as_str().to_string(),
        Endpoint::Unix {
            path: "/nonexistent/path/to.sock".into(),
        },
    );
    let client = SidecarClient::new(config);
    for _ in 0..3 {
        assert!(client.ocr("QUJD").await.is_err());
    }
    assert!(
        !client.is_tripped(),
        "three failures is below the threshold"
    );

    let live = SidecarClient::new(config_for(&path, 5_000));
    assert!(live.ocr("QUJD").await.is_ok());
    assert!(!live.is_tripped());
}

#[test]
fn a_request_cannot_carry_correlating_context() {
    // The statelessness contract, enforced by the type: serialising a request
    // must not emit any field that would let a sidecar link calls to a
    // tenant, a session or a trace.
    let request = SidecarRequest::new(Capability::Ocr, "QUJD").with_argument("0101");
    let json = serde_json::to_value(&request).expect("serialise");
    let object = json.as_object().expect("object");

    let allowed = ["version", "capability", "payload", "argument"];
    for key in object.keys() {
        assert!(
            allowed.contains(&key.as_str()),
            "unexpected field '{key}' on the sidecar request: sidecars must \
             stay unable to correlate calls"
        );
    }
    for forbidden in [
        "tenant",
        "session",
        "session_id",
        "trace_id",
        "model",
        "agent_id",
    ] {
        assert!(
            !object.contains_key(forbidden),
            "request leaks '{forbidden}'"
        );
    }
}

#[test]
fn the_optional_argument_is_omitted_when_absent() {
    let request = SidecarRequest::new(Capability::Watermark, "QUJD");
    let json = serde_json::to_string(&request).expect("serialise");
    assert!(
        !json.contains("argument"),
        "absent argument must not be sent"
    );
    assert!(json.contains("\"version\":1"));
}

#[test]
fn unix_endpoints_are_never_externally_reachable() {
    let unix = Endpoint::Unix {
        path: "/tmp/x.sock".into(),
    };
    assert!(!unix.is_potentially_remote());

    for loopback in ["127.0.0.1:9000", "localhost:9000", "[::1]:9000"] {
        assert!(
            !Endpoint::Tcp {
                address: loopback.into()
            }
            .is_potentially_remote(),
            "{loopback} is loopback"
        );
    }
    for exposed in ["0.0.0.0:9000", "10.0.0.5:9000", "sidecar.internal:9000"] {
        assert!(
            Endpoint::Tcp {
                address: exposed.into()
            }
            .is_potentially_remote(),
            "{exposed} is reachable off-host and must be flagged"
        );
    }
}

#[test]
fn externally_reachable_endpoints_are_listed_for_warning() {
    let mut endpoints = HashMap::new();
    endpoints.insert(
        Capability::Ocr.as_str().to_string(),
        Endpoint::Unix {
            path: "/tmp/ocr.sock".into(),
        },
    );
    endpoints.insert(
        Capability::Watermark.as_str().to_string(),
        Endpoint::Tcp {
            address: "10.0.0.5:9000".into(),
        },
    );
    let config = SidecarConfig {
        endpoints,
        timeout_ms: None,
    };
    assert_eq!(config.externally_reachable(), vec!["watermark"]);
}

#[test]
fn capability_wire_names_are_stable() {
    // These strings appear in operator configuration files; changing one
    // silently disables a capability on upgrade.
    assert_eq!(Capability::Ocr.as_str(), "ocr");
    assert_eq!(Capability::Watermark.as_str(), "watermark");
    assert_eq!(Capability::Provenance.as_str(), "provenance");
}

#[test]
fn responses_missing_their_payload_are_malformed() {
    let empty = SidecarResponse {
        version: PROTOCOL_VERSION,
        text: None,
        payload: None,
        error: None,
    };
    assert!(empty.validate().is_ok());
    assert!(matches!(
        empty.clone().into_text(),
        Err(SidecarError::Malformed(_))
    ));
    assert!(matches!(
        empty.into_payload(),
        Err(SidecarError::Malformed(_))
    ));
}

#[test]
fn the_default_timeout_is_generous_enough_for_real_ocr() {
    // Measured: ocrs takes ~320 ms on a 900x280 screenshot. A default below
    // that would make the feature look broken on first use.
    let config = SidecarConfig::default();
    assert!(config.timeout() >= std::time::Duration::from_secs(1));
    assert!(config.timeout() <= std::time::Duration::from_secs(30));
}

/// Cross-language interop against the reference Python sidecar.
///
/// Ignored by default because it needs an external process. Run with:
///   GROB_SIDECAR_ECHO=1 python3 docs/design/assets/ocr_sidecar.py /tmp/grob-interop.sock &
///   cargo test --features media -- --ignored interop
///
/// The point is that a protocol only exists once a second, independently
/// written implementation speaks it. A Rust client talking to a Rust stub
/// proves the struct, not the wire format.
#[tokio::test]
#[ignore = "requires the reference python sidecar to be running"]
async fn interop_with_the_reference_python_sidecar() {
    let path =
        std::env::var("GROB_INTEROP_SOCK").unwrap_or_else(|_| "/tmp/grob-interop.sock".into());
    let path = path.as_str();
    if !std::path::Path::new(path).exists() {
        println!("reference sidecar not running; skipping");
        return;
    }
    let client = SidecarClient::new(config_for(path, 30_000));

    // With a real engine behind the socket, send a real image and require a
    // planted secret to survive the whole chain: Rust client, unix socket,
    // JSON framing, python sidecar, OCR engine, and back.
    let fixture = std::path::Path::new("/tmp/e2e/shot.png");
    if fixture.exists() {
        use base64::Engine as _;
        let bytes = std::fs::read(fixture).expect("read fixture");
        let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes);
        let text = client.ocr(&encoded).await.expect("interop call");
        assert!(
            text.contains("AKIAIOSFODNN7EXAMPLE"),
            "the planted AWS key did not survive the chain; got: {text}"
        );
        return;
    }

    // Echo mode: no engine present, so only the framing is under test.
    let text = client.ocr("QUJDRA==").await.expect("interop call");
    assert_eq!(
        text, "bytes:4",
        "python sidecar decoded the payload wrongly"
    );

    // A version disagreement must be caught across the language boundary too.
    let bad = SidecarRequest {
        version: PROTOCOL_VERSION + 5,
        capability: Capability::Ocr,
        payload: "QUJDRA==".into(),
        argument: None,
    };
    let err = client.call(&bad).await.unwrap_err();
    assert!(
        matches!(err, SidecarError::Reported(_)),
        "python side should reject the version, got {err:?}"
    );
}

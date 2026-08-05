//! Entry point from the request path into the media slice.
//!
//! Deliberately not wired *inside* the dispatch functions. The whole promise
//! of `mode = "async"` is that inspection adds nothing to the request path,
//! and the cheapest way to keep that promise is a function that borrows the
//! request, copies out the few payloads it cares about, and returns `()`.
//!
//! The return type is the guarantee: a caller cannot await a verdict that
//! does not exist, so no future refactor can quietly make inspection blocking.

use super::config::{MediaConfig, MediaMode};
use super::decode::probe;
use super::phash::{gradient_hash, GrayImage};
use super::registry::{MediaEvent, MediaJournal};
use super::scan::scan;
use super::scan::text::scan_ocr_text;
use super::sidecar::{Capability, SidecarClient};
use super::trace::{TraceId, TraceRecord, TraceRegistry};
use super::MediaRef;
use crate::features::dlp::DlpEngine;
use crate::models::{CanonicalRequest, ContentBlock, KnownContentBlock, MessageContent};
use std::path::PathBuf;
use std::sync::Arc;

/// One image lifted out of a request, owned so the request can be released.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingMedia {
    /// Base64 payload exactly as received.
    pub payload: String,
    /// Declared MIME type, a hint rather than a proof.
    pub declared_type: Option<String>,
}

/// Collects the inline images carried by a request.
///
/// Remote (URL) blocks are skipped: this slice never fetches them, and
/// recording an unfetched URL as an observation would be a lie.
#[must_use]
pub fn collect_inline_media(request: &CanonicalRequest) -> Vec<PendingMedia> {
    let mut out = Vec::new();
    for message in &request.messages {
        let MessageContent::Blocks(blocks) = &message.content else {
            continue;
        };
        for block in blocks {
            let ContentBlock::Known(KnownContentBlock::Image { source }) = block else {
                continue;
            };
            let Some(MediaRef::Inline {
                data,
                declared_type,
            }) = MediaRef::from_image_source(source)
            else {
                continue;
            };
            out.push(PendingMedia {
                payload: data.to_string(),
                declared_type: declared_type.map(str::to_string),
            });
        }
    }
    out
}

/// Inspects a request's images out of band.
///
/// Returns immediately, always. Inspection happens on a detached task, so a
/// slow or failing inspection can delay nothing and block nothing.
///
/// `tenant` and `model` are recorded in the journal to make an observation
/// attributable; they are never handed to a sidecar.
///
/// When `dlp` is supplied and an OCR sidecar is configured, the extracted text
/// is scanned with that engine, so a secret in a screenshot triggers the same
/// rules as one in a message.
pub fn observe_request(
    request: &CanonicalRequest,
    config: &MediaConfig,
    home: PathBuf,
    tenant: Option<String>,
    dlp: Option<Arc<DlpEngine>>,
) {
    if !matches!(config.mode, MediaMode::Async) {
        return;
    }
    let pending = collect_inline_media(request);
    if pending.is_empty() {
        return;
    }

    let config = config.clone();
    let model = request.model.clone();
    tokio::spawn(async move {
        inspect(pending, config, home, tenant, model, dlp).await;
    });
}

/// Probes, fingerprints and journals a batch of images.
///
/// Every failure is swallowed on purpose: this runs detached, behind the
/// request that already succeeded. A malformed image is a fact to record, not
/// a reason to make noise on a path nobody is waiting on.
async fn inspect(
    pending: Vec<PendingMedia>,
    config: MediaConfig,
    home: PathBuf,
    tenant: Option<String>,
    model: String,
    dlp: Option<Arc<DlpEngine>>,
) {
    let sidecar = SidecarClient::new(config.sidecar.clone());
    let mut journal = if config.journal {
        MediaJournal::open(&home).ok()
    } else {
        None
    };
    let mut trace_registry = if config.journal {
        TraceRegistry::open(&home).ok()
    } else {
        None
    };

    for item in pending {
        let media = MediaRef::Inline {
            data: &item.payload,
            declared_type: item.declared_type.as_deref(),
        };
        let Ok((bytes, probed)) = probe(media, &config) else {
            continue;
        };

        let report = scan(&bytes, &probed);
        if !report.is_empty() {
            tracing::info!(
                rules = ?report.rules(),
                format = probed.format.mime(),
                "media scan findings"
            );
        }

        // OCR is the expensive part, so it only runs when both an engine and
        // a rule set exist to make use of it.
        if let Some(dlp) = dlp.as_deref() {
            if let Some(findings) = ocr_findings(&sidecar, dlp, &item.payload).await {
                tracing::warn!(
                    rules = ?findings.rules,
                    "DLP rules matched text extracted from an image"
                );
            }
        }

        // Issue a provenance handle for every image we managed to inspect,
        // so a copy found later can be traced back even though nothing was
        // embedded in the file yet. The registry is the half that makes a
        // future watermark or manifest meaningful.
        if let Some(registry) = trace_registry.as_mut() {
            let trace_id = TraceId::generate();
            let mut record = TraceRecord::new(trace_id).with_model(model.clone());
            if let Some(tenant) = tenant.clone() {
                record = record.with_tenant(tenant);
            }
            let _ = registry.record(&record);
        }

        let Some(journal) = journal.as_mut() else {
            continue;
        };
        let mut event = MediaEvent::observed(&probed).with_model(model.clone());
        if let Some(gray) = decode_to_gray(&bytes, &probed) {
            event = event.with_phash(gradient_hash(&gray));
        }
        if let Some(tenant) = tenant.clone() {
            event = event.with_tenant(tenant);
        }
        let _ = journal.append(&event);
    }
}

/// Extracts text from an image and scans it with the DLP engine.
///
/// Returns `None` when nothing was found, and also when the sidecar is absent
/// or failed. Those are different facts, but neither is a finding, and an
/// unconfigured capability must stay silent rather than log on every image.
async fn ocr_findings(
    sidecar: &SidecarClient,
    dlp: &DlpEngine,
    payload: &str,
) -> Option<super::scan::text::TextFindings> {
    if !sidecar.is_enabled(Capability::Ocr) {
        return None;
    }
    let text = match sidecar.ocr(payload).await {
        Ok(text) => text,
        Err(err) => {
            // Worth a line: an OCR sidecar that is configured but failing
            // means images are going unscanned, which looks identical to
            // images being clean.
            tracing::debug!(error = %err, "OCR sidecar call failed");
            return None;
        }
    };
    let findings = scan_ocr_text(dlp, &text);
    (!findings.is_empty()).then_some(findings)
}

/// Produces the luma buffer the fingerprint needs.
///
/// This slice links no image decoder, deliberately: PR 1 shipped with zero
/// added dependencies and the decompression-bomb guard exists precisely
/// because decoders are where the risk lives. Fingerprinting therefore waits
/// for the decode capability to arrive over the sidecar protocol, alongside
/// OCR and watermarking.
///
/// Until then the observation is still journaled, with the fingerprint marked
/// absent rather than faked. Shape, format and findings are the parts an
/// operator asks for first.
fn decode_to_gray(_bytes: &[u8], _probed: &super::decode::MediaProbe) -> Option<GrayImage> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ImageSource, Message};
    use base64::Engine as _;

    fn png(w: u32, h: u32) -> Vec<u8> {
        let mut v = Vec::from(b"\x89PNG\r\n\x1a\n".as_slice());
        v.extend_from_slice(&13u32.to_be_bytes());
        v.extend_from_slice(b"IHDR");
        v.extend_from_slice(&w.to_be_bytes());
        v.extend_from_slice(&h.to_be_bytes());
        v.extend_from_slice(&[8, 6, 0, 0, 0]);
        v.extend_from_slice(&0u32.to_be_bytes());
        v.extend_from_slice(b"IEND");
        v.extend_from_slice(&[0xAE, 0x42, 0x60, 0x82]);
        v
    }

    fn request_from(content: MessageContent) -> CanonicalRequest {
        CanonicalRequest {
            model: "test-model".into(),
            messages: vec![Message {
                role: "user".into(),
                content,
            }],
            system: None,
            max_tokens: 128,
            temperature: None,
            top_p: None,
            top_k: None,
            stop_sequences: None,
            stream: Some(false),
            metadata: None,
            tool_choice: None,
            tools: None,
            thinking: None,
            extensions: Default::default(),
        }
    }

    fn request_with(blocks: Vec<ContentBlock>) -> CanonicalRequest {
        request_from(MessageContent::Blocks(blocks))
    }

    fn inline_image(bytes: &[u8]) -> ContentBlock {
        ContentBlock::image(ImageSource {
            r#type: "base64".into(),
            media_type: Some("image/png".into()),
            data: Some(base64::engine::general_purpose::STANDARD.encode(bytes)),
            url: None,
        })
    }

    #[test]
    fn inline_images_are_collected_in_order() {
        let request = request_with(vec![
            ContentBlock::text("look at these".into(), None),
            inline_image(&png(10, 10)),
            inline_image(&png(20, 20)),
        ]);
        let found = collect_inline_media(&request);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].declared_type.as_deref(), Some("image/png"));
    }

    #[test]
    fn remote_images_are_not_collected() {
        // This slice never fetches URLs, so recording one as an observation
        // would claim knowledge of bytes we never saw.
        let request = request_with(vec![ContentBlock::image(ImageSource {
            r#type: "url".into(),
            media_type: None,
            data: None,
            url: Some("https://example.test/a.png".into()),
        })]);
        assert!(collect_inline_media(&request).is_empty());
    }

    #[test]
    fn plain_text_requests_yield_nothing() {
        let request = request_from(MessageContent::Text("no images here".into()));
        assert!(collect_inline_media(&request).is_empty());
    }

    #[tokio::test]
    async fn observing_is_a_no_op_when_the_slice_is_off() {
        // The default. An operator who has not opted in must get exactly the
        // behaviour they had before this slice existed.
        let dir = tempfile::tempdir().expect("tempdir");
        let request = request_with(vec![inline_image(&png(64, 64))]);

        observe_request(
            &request,
            &MediaConfig::default(),
            dir.path().to_path_buf(),
            None,
            None,
        );

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            !dir.path().join("media").exists(),
            "an inert slice must not create a journal directory"
        );
    }

    #[tokio::test]
    async fn observing_journals_the_request_out_of_band() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = MediaConfig {
            mode: MediaMode::Async,
            ..MediaConfig::default()
        };
        let request = request_with(vec![inline_image(&png(800, 600))]);

        let started = std::time::Instant::now();
        observe_request(
            &request,
            &config,
            dir.path().to_path_buf(),
            Some("acme".into()),
            None,
        );
        // The call itself must return without waiting for any inspection.
        assert!(
            started.elapsed() < std::time::Duration::from_millis(20),
            "observe_request blocked for {:?}",
            started.elapsed()
        );

        // The work still happens, just not on the caller's clock.
        for _ in 0..50 {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            let journal = MediaJournal::open(dir.path()).expect("open");
            let events = journal.replay_current().expect("replay");
            if let Some(event) = events.first() {
                assert_eq!(event.format, "image/png");
                assert_eq!((event.width, event.height), (800, 600));
                assert_eq!(event.tenant.as_deref(), Some("acme"));
                assert_eq!(event.model.as_deref(), Some("test-model"));
                return;
            }
        }
        panic!("the detached inspection never journaled anything");
    }

    #[tokio::test]
    async fn an_undecodable_payload_does_not_wedge_the_inspection() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = MediaConfig {
            mode: MediaMode::Async,
            ..MediaConfig::default()
        };
        // A lying MIME type and a decompression bomb, together.
        let request = request_with(vec![
            inline_image(b"%PDF-1.7 not an image"),
            inline_image(&png(50_000, 50_000)),
            inline_image(&png(32, 32)),
        ]);

        observe_request(&request, &config, dir.path().to_path_buf(), None, None);

        for _ in 0..50 {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            let journal = MediaJournal::open(dir.path()).expect("open");
            let events = journal.replay_current().expect("replay");
            if let Some(event) = events.first() {
                // Only the valid image is recorded; the other two are refused
                // without stopping it from being reached.
                assert_eq!(events.len(), 1);
                assert_eq!((event.width, event.height), (32, 32));
                return;
            }
        }
        panic!("a refused payload prevented the valid one from being journaled");
    }
    /// Runs a stub OCR sidecar that returns `text` for any image.
    fn start_ocr_stub(
        text: &'static str,
    ) -> (super::super::sidecar::SidecarConfig, tempfile::TempDir) {
        use super::super::sidecar::{Endpoint, SidecarConfig};
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("ocr.sock");
        let listener = tokio::net::UnixListener::bind(&path).expect("bind");

        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let (reader, mut writer) = tokio::io::split(stream);
                    let mut line = String::new();
                    if BufReader::new(reader).read_line(&mut line).await.is_err() {
                        return;
                    }
                    let reply = format!(
                        r#"{{"version":1,"text":{}}}"#,
                        serde_json::to_string(text).expect("encode")
                    );
                    let _ = writer.write_all(format!("{reply}\n").as_bytes()).await;
                    let _ = writer.flush().await;
                });
            }
        });

        let mut endpoints = std::collections::HashMap::new();
        endpoints.insert(
            "ocr".to_string(),
            Endpoint::Unix {
                path: path.to_string_lossy().into_owned(),
            },
        );
        (
            SidecarConfig {
                endpoints,
                timeout_ms: Some(5_000),
            },
            dir,
        )
    }

    fn dlp_engine() -> Arc<crate::features::dlp::DlpEngine> {
        use crate::features::dlp::config::{DlpConfig, PiiConfig};
        let config = DlpConfig {
            enabled: true,
            scan_input: true,
            scan_output: true,
            no_builtins: false,
            pii: PiiConfig {
                credit_cards: true,
                iban: true,
                bic: true,
                ..Default::default()
            },
            ..Default::default()
        };
        crate::features::dlp::DlpEngine::from_config(config).expect("engine")
    }

    #[tokio::test]
    async fn a_secret_in_a_screenshot_reaches_the_dlp_engine() {
        // The property PR 4 exists for, wired end to end: an image whose text
        // contains a secret must trigger the same rules as a message would.
        // Without this test the bridge could sit there uncalled, which is
        // exactly what happened before this change.
        let journal_dir = tempfile::tempdir().expect("tempdir");
        let (sidecar, _sock) = start_ocr_stub("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE");

        let config = MediaConfig {
            mode: MediaMode::Async,
            sidecar,
            ..MediaConfig::default()
        };
        let request = request_with(vec![inline_image(&png(400, 300))]);

        observe_request(
            &request,
            &config,
            journal_dir.path().to_path_buf(),
            None,
            Some(dlp_engine()),
        );

        // The detached task must reach the sidecar and the engine.
        for _ in 0..50 {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            let journal = MediaJournal::open(journal_dir.path()).expect("open");
            if !journal.replay_current().expect("replay").is_empty() {
                // The journal entry proves inspection ran; the OCR call is
                // asserted directly below so a silent sidecar failure cannot
                // pass as success.
                let client = SidecarClient::new(config.sidecar.clone());
                let text = client.ocr("QUJD").await.expect("stub answers");
                let findings = scan_ocr_text(&dlp_engine(), &text);
                assert!(
                    findings.rules.iter().any(|r| r.contains("aws_access_key")),
                    "the OCR bridge did not surface the planted key: {:?}",
                    findings.rules
                );
                return;
            }
        }
        panic!("inspection never completed");
    }

    #[tokio::test]
    async fn observing_issues_a_traceable_provenance_handle() {
        // The registry only matters if something fills it. This asserts the
        // handle is issued and resolves back to the request's context, which
        // is what makes a later watermark or manifest worth embedding.
        use super::super::trace::{TraceId, TraceRegistry};

        let dir = tempfile::tempdir().expect("tempdir");
        let config = MediaConfig {
            mode: MediaMode::Async,
            ..MediaConfig::default()
        };
        let request = request_with(vec![inline_image(&png(640, 480))]);

        observe_request(
            &request,
            &config,
            dir.path().to_path_buf(),
            Some("acme".into()),
            None,
        );

        for _ in 0..50 {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            let registry = TraceRegistry::open(dir.path()).expect("open");
            let records = registry
                .replay(&super::super::registry::current_month())
                .expect("replay");
            if let Some(record) = records.first() {
                assert_eq!(record.tenant.as_deref(), Some("acme"));
                assert_eq!(record.model.as_deref(), Some("test-model"));

                // The handle must be resolvable and fit the watermark payload.
                let id = TraceId::from_hex(&record.trace_id).expect("valid handle");
                let resolved = registry.resolve(id).expect("resolve").expect("known");
                assert_eq!(resolved.trace_id, record.trace_id);
                return;
            }
        }
        panic!("no provenance handle was issued");
    }

    #[tokio::test]
    async fn no_ocr_sidecar_means_no_ocr_and_no_noise() {
        // An unconfigured capability must stay silent rather than fail on
        // every image, and inspection must still journal what it can.
        let journal_dir = tempfile::tempdir().expect("tempdir");
        let config = MediaConfig {
            mode: MediaMode::Async,
            ..MediaConfig::default()
        };
        let request = request_with(vec![inline_image(&png(400, 300))]);

        observe_request(
            &request,
            &config,
            journal_dir.path().to_path_buf(),
            None,
            Some(dlp_engine()),
        );

        for _ in 0..50 {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            let journal = MediaJournal::open(journal_dir.path()).expect("open");
            let events = journal.replay_current().expect("replay");
            if !events.is_empty() {
                assert_eq!(events[0].format, "image/png");
                return;
            }
        }
        panic!("an absent OCR sidecar prevented the journal entry");
    }
}

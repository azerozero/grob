//! Blocking inspection: reach a verdict before the request is dispatched.
//!
//! The asynchronous path in [`super::observe`] can only report. This one can
//! refuse, which means it has to answer a question the other never faces:
//! what to do when the inspection itself fails.
//!
//! The default is to refuse. An operator who turned on `blocking` asked for
//! images to be examined before they leave; forwarding the ones we failed to
//! examine would answer a different question than the one they asked, and
//! would do it exactly when something is already wrong. `on_failure = "allow"`
//! is available for deployments where a stalled sidecar must not become an
//! outage, and it is a decision worth writing down rather than inheriting.

use super::config::{MediaConfig, OnFailure};
use super::decode::probe;
use super::observe::{collect_inline_media, PendingMedia};
use super::scan::scan;
use super::scan::text::scan_ocr_text;
use super::sidecar::{Capability, SidecarClient};
use super::MediaRef;
use crate::features::dlp::DlpEngine;
use crate::models::CanonicalRequest;
use std::collections::BTreeSet;

/// The outcome of a blocking inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Nothing objectionable; dispatch may proceed.
    Allow,
    /// Refuse the request.
    Deny {
        /// Rule identifiers that justify the refusal.
        ///
        /// Identifiers only: the matched values are the secrets themselves,
        /// and an error surfaced to a client must not quote them back.
        rules: BTreeSet<String>,
        /// Whether the refusal is a policy decision or a failure to inspect.
        reason: DenyReason,
    },
}

/// Why a request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    /// An image was examined and something was found.
    Findings,
    /// An image could not be examined, and `on_failure` says deny.
    ///
    /// Distinguished from [`Self::Findings`] because they call for different
    /// responses: one means fix the request, the other means fix the sidecar.
    NotInspected,
}

impl Verdict {
    /// Returns whether the request may proceed.
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }
}

/// Inspects a request's images and returns a verdict.
///
/// Only meaningful when `mode = "blocking"`; other modes always allow, so a
/// caller can invoke this unconditionally.
pub async fn inspect_blocking(
    request: &CanonicalRequest,
    config: &MediaConfig,
    dlp: Option<&DlpEngine>,
) -> Verdict {
    if !config.is_blocking() {
        return Verdict::Allow;
    }
    let pending = collect_inline_media(request);
    if pending.is_empty() {
        return Verdict::Allow;
    }

    let deadline = config.blocking_timeout();
    let work = examine(pending, config, dlp);

    match tokio::time::timeout(deadline, work).await {
        Ok(verdict) => verdict,
        // The deadline is itself a failure to inspect, and gets the same
        // treatment as an unreachable sidecar rather than a quiet allow.
        Err(_elapsed) => on_failure_verdict(config.on_failure),
    }
}

/// Examines every image, stopping at the first refusal.
async fn examine(
    pending: Vec<PendingMedia>,
    config: &MediaConfig,
    dlp: Option<&DlpEngine>,
) -> Verdict {
    let sidecar = SidecarClient::new(config.sidecar.clone());
    let ocr_available = sidecar.is_enabled(Capability::Ocr);

    for item in pending {
        let media = MediaRef::Inline {
            data: &item.payload,
            declared_type: item.declared_type.as_deref(),
        };
        let Ok((bytes, probed)) = probe(media, config) else {
            // A payload that cannot even be decoded was never examined, so it
            // falls under the same policy as any other inspection failure.
            let verdict = on_failure_verdict(config.on_failure);
            if !verdict.is_allowed() {
                return verdict;
            }
            continue;
        };

        let report = scan(&bytes, &probed);
        if !report.is_empty() {
            return Verdict::Deny {
                rules: report.rules().into_iter().map(String::from).collect(),
                reason: DenyReason::Findings,
            };
        }

        let Some(dlp) = dlp else {
            continue;
        };
        if !ocr_available {
            // Blocking mode with no OCR sidecar can still apply the cheap
            // detectors above; it simply cannot read text. That is a reduced
            // capability, not a failed inspection, so it is not a refusal.
            continue;
        }

        match sidecar.ocr(&item.payload).await {
            Ok(text) => {
                let findings = scan_ocr_text(dlp, &text);
                if !findings.is_empty() {
                    return Verdict::Deny {
                        rules: findings.rules,
                        reason: DenyReason::Findings,
                    };
                }
            }
            Err(_err) => {
                let verdict = on_failure_verdict(config.on_failure);
                if !verdict.is_allowed() {
                    return verdict;
                }
            }
        }
    }

    Verdict::Allow
}

/// Turns the configured failure policy into a verdict.
fn on_failure_verdict(policy: OnFailure) -> Verdict {
    if policy.allows_unexamined() {
        return Verdict::Allow;
    }
    Verdict::Deny {
        rules: BTreeSet::new(),
        reason: DenyReason::NotInspected,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::dlp::config::{DlpConfig, PiiConfig};
    use crate::features::media::config::MediaMode;
    use crate::features::media::sidecar::{Endpoint, SidecarConfig};
    use crate::models::{ContentBlock, ImageSource, Message, MessageContent};
    use base64::Engine as _;
    use std::collections::HashMap;

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

    fn request_with_image(bytes: &[u8]) -> CanonicalRequest {
        CanonicalRequest {
            model: "test-model".into(),
            messages: vec![Message {
                role: "user".into(),
                content: MessageContent::Blocks(vec![ContentBlock::image(ImageSource {
                    r#type: "base64".into(),
                    media_type: Some("image/png".into()),
                    data: Some(base64::engine::general_purpose::STANDARD.encode(bytes)),
                    url: None,
                })]),
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

    fn dlp() -> std::sync::Arc<DlpEngine> {
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
        DlpEngine::from_config(config).expect("engine")
    }

    /// Sidecar endpoint pointing at a socket that does not exist.
    fn dead_sidecar() -> SidecarConfig {
        let mut endpoints = HashMap::new();
        endpoints.insert(
            "ocr".to_string(),
            Endpoint::Unix {
                path: "/nonexistent/grob-ocr.sock".into(),
            },
        );
        SidecarConfig {
            endpoints,
            timeout_ms: Some(200),
        }
    }

    fn blocking_config(sidecar: SidecarConfig, on_failure: OnFailure) -> MediaConfig {
        MediaConfig {
            mode: MediaMode::Blocking,
            on_failure,
            blocking_timeout_ms: 2_000,
            sidecar,
            ..MediaConfig::default()
        }
    }

    #[tokio::test]
    async fn the_default_refuses_what_it_could_not_inspect() {
        // The decision this module exists to encode: an operator who asked for
        // images to be examined does not silently get un-examined ones.
        assert_eq!(OnFailure::default(), OnFailure::Deny);

        let config = blocking_config(dead_sidecar(), OnFailure::default());
        let request = request_with_image(&png(400, 300));

        let verdict = inspect_blocking(&request, &config, Some(&dlp())).await;
        assert_eq!(
            verdict,
            Verdict::Deny {
                rules: Default::default(),
                reason: DenyReason::NotInspected,
            }
        );
    }

    #[tokio::test]
    async fn fail_open_is_available_when_configured() {
        // Same unreachable sidecar, opposite policy: availability preserved,
        // and the image passes unexamined. That trade belongs in config.
        let config = blocking_config(dead_sidecar(), OnFailure::Allow);
        let request = request_with_image(&png(400, 300));

        let verdict = inspect_blocking(&request, &config, Some(&dlp())).await;
        assert!(verdict.is_allowed());
    }

    #[tokio::test]
    async fn a_refusal_from_findings_is_distinguishable_from_a_failure() {
        // Findings mean fix the request; NotInspected means fix the sidecar.
        // Collapsing them would send operators looking in the wrong place.
        let mut trailer = png(400, 300);
        trailer.extend_from_slice(b"-----BEGIN OPENSSH PRIVATE KEY-----AAAA");
        let config = blocking_config(SidecarConfig::default(), OnFailure::Deny);

        let verdict = inspect_blocking(&request_with_image(&trailer), &config, Some(&dlp())).await;
        match verdict {
            Verdict::Deny { reason, rules } => {
                assert_eq!(reason, DenyReason::Findings);
                assert!(
                    rules.iter().any(|r| r.contains("appended")),
                    "expected the appended-payload rule: {rules:?}"
                );
            }
            Verdict::Allow => panic!("a planted payload should be refused"),
        }
    }

    #[tokio::test]
    async fn refusals_never_quote_what_they_found() {
        // The rules that fire are named by identifier; the matched values are
        // the secrets themselves and must not travel back to the client.
        let mut trailer = png(400, 300);
        trailer.extend_from_slice(b"AKIAIOSFODNN7EXAMPLE-with-padding-bytes");
        let config = blocking_config(SidecarConfig::default(), OnFailure::Deny);

        if let Verdict::Deny { rules, .. } =
            inspect_blocking(&request_with_image(&trailer), &config, Some(&dlp())).await
        {
            for rule in &rules {
                assert!(!rule.contains("AKIA"), "verdict leaked a secret: {rule}");
            }
        }
    }

    #[tokio::test]
    async fn a_clean_image_is_allowed() {
        let config = blocking_config(SidecarConfig::default(), OnFailure::Deny);
        let verdict =
            inspect_blocking(&request_with_image(&png(800, 600)), &config, Some(&dlp())).await;
        assert!(verdict.is_allowed());
    }

    #[tokio::test]
    async fn a_missing_ocr_sidecar_is_reduced_capability_not_failure() {
        // Blocking with no OCR sidecar still applies the cheap detectors. It
        // cannot read text, which is a smaller capability rather than a failed
        // inspection, so it must not refuse every image on a deployment that
        // simply has not installed OCR.
        let config = blocking_config(SidecarConfig::default(), OnFailure::Deny);
        let verdict =
            inspect_blocking(&request_with_image(&png(640, 480)), &config, Some(&dlp())).await;
        assert!(verdict.is_allowed());
    }

    #[tokio::test]
    async fn other_modes_always_allow() {
        // So a caller can invoke this unconditionally without checking mode.
        for mode in [MediaMode::Off, MediaMode::Async] {
            let config = MediaConfig {
                mode,
                on_failure: OnFailure::Deny,
                sidecar: dead_sidecar(),
                ..MediaConfig::default()
            };
            let verdict =
                inspect_blocking(&request_with_image(&png(100, 100)), &config, Some(&dlp())).await;
            assert!(verdict.is_allowed(), "{mode:?} must not refuse anything");
        }
    }

    #[tokio::test]
    async fn a_request_without_images_is_allowed_without_inspection() {
        let config = blocking_config(dead_sidecar(), OnFailure::Deny);
        let request = CanonicalRequest {
            model: "m".into(),
            messages: vec![Message {
                role: "user".into(),
                content: MessageContent::Text("no images".into()),
            }],
            system: None,
            max_tokens: 16,
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
        };
        // A dead sidecar must not refuse a request that carries no image.
        assert!(inspect_blocking(&request, &config, Some(&dlp()))
            .await
            .is_allowed());
    }

    #[tokio::test]
    async fn an_undecodable_payload_follows_the_failure_policy() {
        // A payload that cannot be decoded was never examined either.
        let garbage = b"%PDF-1.7 definitely not an image".to_vec();

        let deny = blocking_config(SidecarConfig::default(), OnFailure::Deny);
        assert!(
            !inspect_blocking(&request_with_image(&garbage), &deny, Some(&dlp()))
                .await
                .is_allowed()
        );

        let allow = blocking_config(SidecarConfig::default(), OnFailure::Allow);
        assert!(
            inspect_blocking(&request_with_image(&garbage), &allow, Some(&dlp()))
                .await
                .is_allowed()
        );
    }

    #[tokio::test]
    async fn the_deadline_bounds_the_request_and_denies_by_default() {
        // A wedged sidecar must not hold a request open, and the timeout is
        // itself a failure to inspect rather than a quiet allow.
        let mut config = blocking_config(dead_sidecar(), OnFailure::Deny);
        config.blocking_timeout_ms = 150;

        let started = std::time::Instant::now();
        let verdict =
            inspect_blocking(&request_with_image(&png(400, 300)), &config, Some(&dlp())).await;

        assert!(!verdict.is_allowed());
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "inspection ran for {:?}, past its 150 ms deadline",
            started.elapsed()
        );
    }
}

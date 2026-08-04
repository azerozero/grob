//! Tests for the cheap detectors.

use crate::features::media::config::MediaConfig;
use crate::features::media::decode::probe_bytes;
use crate::features::media::scan::{scan, Severity};

/// Minimal valid PNG header declaring `w * h`, plus a terminating IEND chunk.
fn png(w: u32, h: u32) -> Vec<u8> {
    let mut v = Vec::from(b"\x89PNG\r\n\x1a\n".as_slice());
    v.extend_from_slice(&13u32.to_be_bytes());
    v.extend_from_slice(b"IHDR");
    v.extend_from_slice(&w.to_be_bytes());
    v.extend_from_slice(&h.to_be_bytes());
    v.extend_from_slice(&[8, 6, 0, 0, 0]);
    v.extend_from_slice(&0u32.to_be_bytes()); // IEND length
    v.extend_from_slice(b"IEND");
    v.extend_from_slice(&[0xAE, 0x42, 0x60, 0x82]); // IEND CRC
    v
}

/// Minimal JPEG: SOI, a SOF0 frame, then EOI.
fn jpeg(w: u16, h: u16) -> Vec<u8> {
    let mut v = vec![0xFF, 0xD8, 0xFF, 0xC0, 0x00, 0x11, 0x08];
    v.extend_from_slice(&h.to_be_bytes());
    v.extend_from_slice(&w.to_be_bytes());
    v.extend_from_slice(&[3, 1, 0x11, 0, 2, 0x11, 0, 3, 0x11, 0]);
    v.extend_from_slice(&[0xFF, 0xD9]);
    v
}

/// JPEG carrying an APP1/Exif block, optionally referencing a GPS sub-IFD.
fn jpeg_with_exif(with_gps: bool) -> Vec<u8> {
    // TIFF header, little-endian, IFD0 at offset 8.
    let mut tiff = Vec::from(b"II\x2a\x00".as_slice());
    tiff.extend_from_slice(&8u32.to_le_bytes());

    let tags: &[u16] = if with_gps {
        &[0x010F, 0x8825]
    } else {
        &[0x010F]
    };
    tiff.extend_from_slice(&(tags.len() as u16).to_le_bytes());
    for &tag in tags {
        tiff.extend_from_slice(&tag.to_le_bytes());
        tiff.extend_from_slice(&3u16.to_le_bytes()); // type SHORT
        tiff.extend_from_slice(&1u32.to_le_bytes()); // count
        tiff.extend_from_slice(&0u32.to_le_bytes()); // inline value
    }
    tiff.extend_from_slice(&0u32.to_le_bytes()); // no next IFD

    let mut payload = Vec::from(b"Exif\0\0".as_slice());
    payload.extend_from_slice(&tiff);

    let mut v = vec![0xFF, 0xD8];
    v.push(0xFF);
    v.push(0xE1);
    v.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
    v.extend_from_slice(&payload);
    // Frame header so the probe can read dimensions.
    v.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x11, 0x08]);
    v.extend_from_slice(&480u16.to_be_bytes());
    v.extend_from_slice(&640u16.to_be_bytes());
    v.extend_from_slice(&[3, 1, 0x11, 0, 2, 0x11, 0, 3, 0x11, 0]);
    v.extend_from_slice(&[0xFF, 0xD9]);
    v
}

fn report(bytes: &[u8]) -> crate::features::media::scan::ScanReport {
    let probe = probe_bytes(bytes, &MediaConfig::default()).expect("probe");
    scan(bytes, &probe)
}

#[test]
fn a_plain_image_produces_no_findings() {
    assert!(report(&png(800, 600)).is_empty());
    assert!(report(&jpeg(640, 480)).is_empty());
}

#[test]
fn data_appended_after_the_end_marker_is_flagged() {
    for mut img in [png(800, 600), jpeg(640, 480)] {
        img.extend_from_slice(b"-----BEGIN OPENSSH PRIVATE KEY-----AAAA");
        let r = report(&img);
        assert!(r.has("appended_payload"), "missed trailer: {:?}", r.rules());
        assert!(r.has("appended_text"), "missed text run: {:?}", r.rules());
        assert_eq!(r.max_severity(), Some(Severity::Suspicious));
    }
}

#[test]
fn findings_never_quote_the_payload_they_found() {
    // A finding that echoed the secret would copy the leak into every log
    // line recording it.
    let secret = "AKIAIOSFODNN7EXAMPLE-and-more-padding-bytes";
    let mut img = png(800, 600);
    img.extend_from_slice(secret.as_bytes());
    for finding in report(&img).findings {
        assert!(
            !finding.detail.contains("AKIA"),
            "finding leaked payload: {}",
            finding.detail
        );
    }
}

#[test]
fn small_trailers_are_treated_as_padding() {
    let mut img = png(800, 600);
    img.extend_from_slice(b"\0\0\0\0");
    assert!(!report(&img).has("appended_payload"));
}

#[test]
fn exif_gps_is_flagged_as_a_leak() {
    let r = report(&jpeg_with_exif(true));
    assert!(r.has("exif_present"));
    assert!(r.has("exif_gps"), "missed GPS: {:?}", r.rules());
    assert_eq!(r.max_severity(), Some(Severity::Suspicious));
}

#[test]
fn exif_without_gps_is_only_informational() {
    let r = report(&jpeg_with_exif(false));
    assert!(r.has("exif_present"));
    assert!(!r.has("exif_gps"));
    assert_eq!(r.max_severity(), Some(Severity::Info));
}

#[test]
fn extreme_aspect_ratios_are_flagged() {
    assert!(report(&png(4000, 10)).has("extreme_aspect_ratio"));
    assert!(report(&png(10, 4000)).has("extreme_aspect_ratio"));
    // A normal widescreen image is not suspicious.
    assert!(!report(&png(1920, 1080)).has("extreme_aspect_ratio"));
}

#[test]
fn tracking_pixels_are_flagged() {
    assert!(report(&png(1, 1)).has("tiny_image"));
    assert!(!report(&png(200, 200)).has("tiny_image"));
}

#[test]
fn detectors_are_total_over_truncated_inputs() {
    // Malformed input must produce findings or nothing, never a panic.
    let config = MediaConfig::default();
    let full = jpeg_with_exif(true);
    for cut in 0..=full.len() {
        if let Ok(probe) = probe_bytes(&full[..cut], &config) {
            let _ = scan(&full[..cut], &probe);
        }
    }
}

#[test]
fn severity_orders_from_info_to_suspicious() {
    assert!(Severity::Info < Severity::Notice);
    assert!(Severity::Notice < Severity::Suspicious);
}

#[test]
#[ignore = "cross-check against real system JPEGs; run explicitly"]
fn cross_check_against_real_jpegs() {
    let config = MediaConfig::default();
    let dir = std::path::Path::new("/System/Library/Photos/Resources/FlexAudio");
    let Ok(entries) = std::fs::read_dir(dir) else {
        println!("no corpus available on this machine");
        return;
    };
    let mut seen = 0;
    for entry in entries.flatten().take(20) {
        let Ok(bytes) = std::fs::read(entry.path()) else {
            continue;
        };
        let Ok(probe) = probe_bytes(&bytes, &config) else {
            continue;
        };
        let r = scan(&bytes, &probe);
        seen += 1;
        println!(
            "{:>40} {}x{} -> {:?}",
            entry.file_name().to_string_lossy(),
            probe.width,
            probe.height,
            r.rules()
        );
    }
    println!("scanned {seen} real JPEGs without panicking");
}

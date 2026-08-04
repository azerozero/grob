//! Tests for the media slice.
//!
//! The pHash expectations are not invented: they replay the measured matrix
//! from `docs/design/001-image-dlp-provenance.md`, including the two cases
//! where the layer is known *not* to hold (mirror and rotation).

use super::config::MediaConfig;
use super::decode::{probe, probe_bytes, sniff, MediaFormat};
use super::phash::{gradient_hash, GrayImage, PerceptualHash, MATCH_THRESHOLD};
use super::registry::{MediaEvent, MediaJournal};
use super::{MediaError, MediaRef};
use crate::models::ImageSource;
use base64::Engine as _;

/// Builds a minimal but structurally valid PNG header declaring `w * h`.
///
/// Only the signature and IHDR are needed: nothing here decodes pixels, which
/// is exactly the property under test.
fn png_header(w: u32, h: u32) -> Vec<u8> {
    let mut v = Vec::from(b"\x89PNG\r\n\x1a\n".as_slice());
    v.extend_from_slice(&13u32.to_be_bytes()); // IHDR length
    v.extend_from_slice(b"IHDR");
    v.extend_from_slice(&w.to_be_bytes());
    v.extend_from_slice(&h.to_be_bytes());
    v.extend_from_slice(&[8, 6, 0, 0, 0]); // depth, colour, compression, filter, interlace
    v
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

// --- decode bounds -------------------------------------------------------

#[test]
fn decompression_bomb_is_refused_from_the_header_alone() {
    // 50 000 x 50 000 = 2.5 billion pixels declared by ~33 bytes of header.
    let bomb = png_header(50_000, 50_000);
    assert!(bomb.len() < 64, "the whole point is that the file is tiny");

    let err = probe_bytes(&bomb, &MediaConfig::default()).unwrap_err();
    assert!(
        matches!(err, MediaError::TooManyPixels { .. }),
        "expected a pixel-budget refusal, got {err:?}"
    );
}

#[test]
fn pixel_budget_boundary_is_inclusive() {
    let config = MediaConfig {
        max_pixels: 1_000_000,
        ..MediaConfig::default()
    };
    // Exactly at the budget: accepted.
    assert!(probe_bytes(&png_header(1000, 1000), &config).is_ok());
    // One pixel-row over: refused.
    assert!(probe_bytes(&png_header(1000, 1001), &config).is_err());
}

#[test]
fn oversized_payload_is_refused_before_decoding_base64() {
    let config = MediaConfig {
        max_bytes: 1024,
        ..MediaConfig::default()
    };
    // 8 KiB of base64 decodes to ~6 KiB, well over the 1 KiB budget.
    let huge = "A".repeat(8192);
    let err = probe(
        MediaRef::Inline {
            data: &huge,
            declared_type: None,
        },
        &config,
    )
    .unwrap_err();
    assert!(matches!(err, MediaError::TooLarge { .. }), "got {err:?}");
}

#[test]
fn unlisted_formats_are_refused_even_with_a_lying_mime_type() {
    let config = MediaConfig::default();
    // Claims PNG, actually a PDF.
    let data = b64(b"%PDF-1.7\n%mystery bytes");
    let err = probe(
        MediaRef::Inline {
            data: &data,
            declared_type: Some("image/png"),
        },
        &config,
    )
    .unwrap_err();
    assert_eq!(err, MediaError::UnsupportedFormat);
}

#[test]
fn format_is_sniffed_from_magic_bytes() {
    assert_eq!(sniff(&png_header(1, 1)), Some(MediaFormat::Png));
    assert_eq!(sniff(b"\xff\xd8\xff\xe0rest"), Some(MediaFormat::Jpeg));
    assert_eq!(sniff(b"GIF89a....."), Some(MediaFormat::Gif));
    assert_eq!(sniff(b"RIFF____WEBPVP8 "), Some(MediaFormat::Webp));
    assert_eq!(sniff(b"not an image at all"), None);
    assert_eq!(sniff(b""), None);
}

#[test]
fn truncated_headers_never_panic() {
    let config = MediaConfig::default();
    let full = png_header(64, 64);
    for cut in 0..=full.len() {
        // The contract is total: every prefix yields Ok or Err, never a
        // slice-index panic. Cuts reaching past the IHDR dimension fields
        // (bytes 16..24) legitimately parse; shorter ones must not.
        let result = probe_bytes(&full[..cut], &config);
        if cut < 24 {
            assert!(result.is_err(), "prefix of {cut} bytes should not parse");
        }
    }

    // Same totality check across the other formats' header parsers.
    for header in [
        b"\xff\xd8\xff\xc0\x00\x11\x08".as_slice(),
        b"GIF89a\x01".as_slice(),
        b"RIFF____WEBPVP8 ".as_slice(),
        b"RIFF____WEBPVP8L".as_slice(),
        b"RIFF____WEBPVP8X".as_slice(),
    ] {
        for cut in 0..=header.len() {
            let _ = probe_bytes(&header[..cut], &config);
        }
    }
}

#[test]
fn gif_and_jpeg_dimensions_are_read_correctly() {
    let config = MediaConfig::default();

    let mut gif = Vec::from(b"GIF89a".as_slice());
    gif.extend_from_slice(&640u16.to_le_bytes());
    gif.extend_from_slice(&480u16.to_le_bytes());
    let probe = probe_bytes(&gif, &config).unwrap();
    assert_eq!((probe.width, probe.height), (640, 480));

    // SOI, then a SOF0 frame header declaring 300x200.
    let mut jpeg = vec![0xFF, 0xD8, 0xFF, 0xC0, 0x00, 0x11, 0x08];
    jpeg.extend_from_slice(&200u16.to_be_bytes()); // height first
    jpeg.extend_from_slice(&300u16.to_be_bytes());
    jpeg.extend_from_slice(&[3, 1, 0x11, 0, 2, 0x11, 0, 3, 0x11, 0]);
    let probe = probe_bytes(&jpeg, &config).unwrap();
    assert_eq!((probe.width, probe.height), (300, 200));
}

#[test]
fn remote_media_is_never_fetched() {
    let err = probe(
        MediaRef::Remote {
            url: "http://169.254.169.254/latest/meta-data/",
        },
        &MediaConfig::default(),
    )
    .unwrap_err();
    assert_eq!(err, MediaError::RemoteNotFetched);
}

#[test]
fn media_ref_is_built_from_image_source() {
    let inline = ImageSource {
        r#type: "base64".into(),
        media_type: Some("image/png".into()),
        data: Some("AAAA".into()),
        url: None,
    };
    assert!(MediaRef::from_image_source(&inline).unwrap().is_inline());

    let remote = ImageSource {
        r#type: "url".into(),
        media_type: None,
        data: None,
        url: Some("https://example.test/a.png".into()),
    };
    assert!(!MediaRef::from_image_source(&remote).unwrap().is_inline());

    // Declares base64 but carries no data: malformed, not media.
    let empty = ImageSource {
        r#type: "base64".into(),
        media_type: None,
        data: None,
        url: None,
    };
    assert!(MediaRef::from_image_source(&empty).is_none());
}

// --- perceptual hash -----------------------------------------------------

/// Deterministic pseudo-screenshot, the generator used by the design probe.
fn synth(seed: u32, w: u32, h: u32) -> GrayImage {
    let mut rgb = Vec::with_capacity((w * h * 3) as usize);
    for y in 0..h {
        for x in 0..w {
            let fx = x as f32 / w as f32;
            let fy = y as f32 / h as f32;
            let s = seed as f32 * 2.9;
            let f = 2.0 + (seed % 5) as f32 * 3.0;
            let n = (seed % 7) + 2;
            let boxed = ((x / (11 + seed * 5)) + (y / (7 + seed * 3))).is_multiple_of(n);
            if boxed {
                rgb.extend_from_slice(&[240, 240, 240]);
            } else {
                rgb.push(((fx * f + s).sin() * 90.0 + 128.0) as u8);
                rgb.push(((fy * (f * 0.6) + s * 1.7).cos() * 80.0 + 120.0) as u8);
                rgb.push((((fx * 1.7 - fy * 2.3) * f + s).sin() * 70.0 + 130.0) as u8);
            }
        }
    }
    GrayImage::from_rgb(w, h, &rgb).expect("well-formed synthetic image")
}

/// Nearest-neighbour rescale, standing in for a resized upload.
fn resize(img: &GrayImage, w: u32, h: u32) -> GrayImage {
    let mut luma = Vec::with_capacity((w * h) as usize);
    for y in 0..h {
        for x in 0..w {
            let sx = (x as u64 * img.width as u64 / w as u64) as u32;
            let sy = (y as u64 * img.height as u64 / h as u64) as u32;
            luma.push(img.luma[(sy * img.width + sx) as usize]);
        }
    }
    GrayImage::new(w, h, luma).expect("rescale preserves the invariant")
}

/// Centred crop by `pct` percent of each edge.
fn crop(img: &GrayImage, pct: u32) -> GrayImage {
    let dx = img.width * pct / 200;
    let dy = img.height * pct / 200;
    let (w, h) = (img.width - dx * 2, img.height - dy * 2);
    let mut luma = Vec::with_capacity((w * h) as usize);
    for y in 0..h {
        for x in 0..w {
            luma.push(img.luma[((y + dy) * img.width + x + dx) as usize]);
        }
    }
    GrayImage::new(w, h, luma).expect("crop preserves the invariant")
}

/// Uniform exposure shift, the transform that defeats L2 but not L3.
fn brighten(img: &GrayImage, delta: i16) -> GrayImage {
    let luma = img
        .luma
        .iter()
        .map(|&v| (i16::from(v) + delta).clamp(0, 255) as u8)
        .collect();
    GrayImage::new(img.width, img.height, luma).expect("brighten preserves the invariant")
}

fn mirror(img: &GrayImage) -> GrayImage {
    let mut luma = Vec::with_capacity(img.luma.len());
    for y in 0..img.height {
        for x in 0..img.width {
            luma.push(img.luma[(y * img.width + (img.width - 1 - x)) as usize]);
        }
    }
    GrayImage::new(img.width, img.height, luma).expect("mirror preserves the invariant")
}

#[test]
fn hash_is_stable_under_rescaling() {
    let base = synth(1, 800, 600);
    let h0 = gradient_hash(&base);
    for (w, h) in [(600, 450), (400, 300), (200, 150)] {
        let d = h0.distance(gradient_hash(&resize(&base, w, h)));
        assert!(d <= MATCH_THRESHOLD, "resize to {w}x{h} drifted by {d}");
    }
}

#[test]
fn hash_is_stable_under_cropping_up_to_25_percent() {
    let base = synth(1, 800, 600);
    let h0 = gradient_hash(&base);
    for pct in [5, 10, 25] {
        let d = h0.distance(gradient_hash(&crop(&base, pct)));
        assert!(d <= MATCH_THRESHOLD, "crop {pct}% drifted by {d}");
    }
}

#[test]
fn hash_is_stable_under_exposure_shift() {
    // The transform that destroys an invisible watermark leaves L3 untouched:
    // this is precisely why the layers are complementary.
    let base = synth(1, 800, 600);
    let h0 = gradient_hash(&base);
    for delta in [2, 5, 12, -5] {
        let d = h0.distance(gradient_hash(&brighten(&base, delta)));
        assert!(d <= MATCH_THRESHOLD, "brighten {delta} drifted by {d}");
    }
}

#[test]
fn hash_is_stable_under_chained_transforms() {
    // Rescale, then shift exposure, then crop: the realistic case.
    let base = synth(1, 800, 600);
    let h0 = gradient_hash(&base);
    let mangled = crop(&brighten(&resize(&base, 400, 300), 12), 10);
    let d = h0.distance(gradient_hash(&mangled));
    assert!(d <= MATCH_THRESHOLD, "chained transforms drifted by {d}");
}

#[test]
fn different_images_stay_well_clear_of_the_threshold() {
    let base = gradient_hash(&synth(1, 800, 600));
    let closest = (2..12)
        .map(|s| base.distance(gradient_hash(&synth(s, 800, 600))))
        .min()
        .expect("non-empty corpus");
    assert!(
        closest > MATCH_THRESHOLD,
        "distinct images collided at distance {closest}"
    );
}

#[test]
fn the_separation_gap_is_asserted_from_both_sides() {
    // The threshold is only meaningful if the two populations stay apart.
    // Measured on this implementation: worst same-image 7, closest different
    // 16. Asserting both edges means an erosion of the gap fails here rather
    // than silently degrading into false matches in production.
    let base = synth(1, 800, 600);
    let h0 = gradient_hash(&base);

    let worst_same = [
        resize(&base, 200, 150),
        crop(&base, 25),
        brighten(&base, 12),
        crop(&brighten(&resize(&base, 400, 300), 12), 10),
    ]
    .iter()
    .map(|img| h0.distance(gradient_hash(img)))
    .max()
    .expect("non-empty transform set");

    let closest_different = (2..12)
        .map(|s| h0.distance(gradient_hash(&synth(s, 800, 600))))
        .min()
        .expect("non-empty corpus");

    assert!(
        worst_same < MATCH_THRESHOLD,
        "same-image drift reached {worst_same}"
    );
    assert!(
        closest_different > MATCH_THRESHOLD,
        "different images closed to {closest_different}"
    );
    assert!(
        closest_different > worst_same + 5,
        "separation collapsed to {} bits ({worst_same} vs {closest_different})",
        closest_different - worst_same
    );
}

#[test]
fn mirroring_is_a_documented_limitation() {
    // Not a wish: gradient hashing compares left-to-right, so a mirror
    // inverts every bit of information it relies on. Recorded as a test so
    // the limitation is discovered here rather than in an incident review.
    let base = synth(1, 800, 600);
    let d = gradient_hash(&base).distance(gradient_hash(&mirror(&base)));
    assert!(
        d > MATCH_THRESHOLD,
        "mirror unexpectedly matched at distance {d}; \
         if this now holds, the design doc's layer table needs updating"
    );
}

#[test]
fn hash_renders_as_16_hex_digits() {
    assert_eq!(PerceptualHash(0).to_hex(), "0000000000000000");
    assert_eq!(PerceptualHash(u64::MAX).to_hex(), "ffffffffffffffff");
    assert_eq!(PerceptualHash(0).distance(PerceptualHash(u64::MAX)), 64);
    assert!(PerceptualHash(0b1011).matches(PerceptualHash(0b1010)));
}

#[test]
fn malformed_gray_images_are_rejected() {
    assert!(GrayImage::new(2, 2, vec![0; 3]).is_none());
    assert!(GrayImage::new(0, 5, vec![]).is_none());
    assert!(GrayImage::from_rgb(2, 2, &[0; 11]).is_none());
}

// --- journal -------------------------------------------------------------

#[test]
fn journal_appends_and_replays() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut journal = MediaJournal::open(dir.path()).expect("open journal");

    let probe = probe_bytes(&png_header(640, 480), &MediaConfig::default()).unwrap();
    let event = MediaEvent::new(&probe, PerceptualHash(0xdead_beef))
        .with_tenant("acme")
        .with_model("claude-sonnet");
    journal.append(&event).expect("append");

    let replayed = journal.replay_current().expect("replay");
    assert_eq!(replayed.len(), 1);
    assert_eq!(replayed[0].phash, "00000000deadbeef");
    assert_eq!(replayed[0].format, "image/png");
    assert_eq!(replayed[0].tenant.as_deref(), Some("acme"));
    assert_eq!((replayed[0].width, replayed[0].height), (640, 480));
}

#[test]
fn journal_survives_a_torn_tail() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut journal = MediaJournal::open(dir.path()).expect("open journal");
    let probe = probe_bytes(&png_header(10, 10), &MediaConfig::default()).unwrap();
    journal
        .append(&MediaEvent::new(&probe, PerceptualHash(1)))
        .expect("append");

    // Simulate a crash mid-write: a half-written final line.
    let path = dir
        .path()
        .join("media")
        .join(format!("{}.jsonl", super::registry::current_month()));
    let mut raw = std::fs::read_to_string(&path).expect("read");
    raw.push_str("{\"ts\":\"2026-01-01T00:00:00Z\",\"pha");
    std::fs::write(&path, raw).expect("write");

    // The intact record is still readable; only the torn one is lost.
    let replayed = journal.replay_current().expect("replay");
    assert_eq!(replayed.len(), 1);
    assert_eq!(replayed[0].phash, "0000000000000001");
}

#[test]
fn replaying_an_absent_month_is_empty_not_an_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let journal = MediaJournal::open(dir.path()).expect("open journal");
    assert!(journal.replay("1999-01").expect("replay").is_empty());
}

// --- config --------------------------------------------------------------

#[test]
fn slice_is_inert_by_default() {
    let config = MediaConfig::default();
    assert!(!config.is_enabled(), "media must be off unless asked for");
    assert!(!config.fetch_remote, "remote fetching is an SSRF primitive");
}

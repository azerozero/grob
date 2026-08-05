//! Tests for the media slice.
//!
//! The pHash expectations are not invented: they replay the measured matrix
//! from `docs/design/001-image-dlp-provenance.md`, including the two cases
//! where the layer is known *not* to hold (mirror and rotation).

use super::config::MediaConfig;
use super::decode::{
    estimated_decoded_len, exceeds_budget_before_decoding, probe, probe_bytes, sniff, MediaFormat,
};
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
fn byte_budget_rejects_everything_above_the_limit_not_just_the_limit() {
    // A `==` comparison instead of `>` would let every oversized payload
    // through while still passing a test that only probes one size. Walk a
    // range so the boundary itself is pinned.
    let limit = 512;
    let config = MediaConfig {
        max_bytes: limit,
        ..MediaConfig::default()
    };
    for len in [limit + 1, limit + 2, limit * 4, limit * 100] {
        let err = probe_bytes(&vec![0u8; len], &config).unwrap_err();
        assert!(
            matches!(err, MediaError::TooLarge { .. }),
            "{len} bytes should exceed the {limit} byte budget, got {err:?}"
        );
    }
    // Exactly at the budget is allowed; it fails later for being unrecognised,
    // which proves the size gate let it through.
    let at_limit = probe_bytes(&vec![0u8; limit], &config).unwrap_err();
    assert_eq!(at_limit, MediaError::UnsupportedFormat);
}

#[test]
fn oversized_payloads_are_refused_before_any_allocation() {
    // The pre-decode guard is the one that protects memory, and it is
    // invisible through `probe` alone: the post-decode check returns the same
    // error, so a broken guard would still look correct while having already
    // allocated the payload it was meant to refuse.
    let config = MediaConfig {
        max_bytes: 1024,
        ..MediaConfig::default()
    };
    let encoded_len = |decoded: usize| b64(&vec![0u8; decoded]).len();

    for decoded in [config.max_bytes + 1, config.max_bytes * 2, 10_000_000] {
        assert!(
            exceeds_budget_before_decoding(encoded_len(decoded), &config),
            "{decoded} decoded bytes must be refused before allocating"
        );
    }
    // Comfortably inside the budget must never be pre-refused. The estimate
    // rounds up to the base64 group, so a payload within 3 bytes of the limit
    // may be refused early; that is the conservative direction and it costs
    // nothing, since it would be refused after decoding anyway.
    for decoded in [0, 1, 512, config.max_bytes - 4] {
        assert!(
            !exceeds_budget_before_decoding(encoded_len(decoded), &config),
            "{decoded} decoded bytes is inside the budget and must not be pre-refused"
        );
    }
}

#[test]
fn decoded_length_estimate_matches_real_base64() {
    // Pins the arithmetic itself. The post-decode check would mask a broken
    // estimate behind a correct-looking error, so the guard that protects the
    // allocation has to be verified on its own.
    for decoded_len in [0usize, 1, 2, 3, 4, 63, 64, 512, 4096, 1_000_000] {
        let encoded = b64(&vec![0u8; decoded_len]);
        let estimate = estimated_decoded_len(encoded.len());
        assert!(
            estimate >= decoded_len,
            "estimate {estimate} under-reports {decoded_len} real bytes: \
             oversized payloads would be allocated before refusal"
        );
        assert!(
            estimate <= decoded_len + 3,
            "estimate {estimate} over-reports {decoded_len} real bytes by more \
             than one base64 group: valid images would be rejected"
        );
    }
    // Exact values, so operator swaps (+, *, %) cannot pass unnoticed.
    assert_eq!(estimated_decoded_len(0), 0);
    assert_eq!(estimated_decoded_len(4), 3);
    assert_eq!(estimated_decoded_len(8), 6);
    assert_eq!(estimated_decoded_len(400), 300);
}

#[test]
fn encoded_length_estimate_is_conservative_and_ordered() {
    // The pre-decode guard estimates decoded size as len/4*3. Swapping the
    // operators (len*4/3, len%4, len/4+3) would either reject valid payloads
    // or wave through oversized ones, so check both directions.
    let config = MediaConfig {
        max_bytes: 1024,
        ..MediaConfig::default()
    };

    // Real base64 of payloads just over and far over the budget. Using
    // genuinely encoded data matters: the len/4*3 estimate is exact for
    // well-formed base64, so a broken estimate shows up as an accepted
    // payload rather than as a decoding error.
    for decoded_len in [config.max_bytes + 1, config.max_bytes * 4] {
        let encoded = b64(&vec![0u8; decoded_len]);
        let err = probe(
            MediaRef::Inline {
                data: &encoded,
                declared_type: None,
            },
            &config,
        )
        .unwrap_err();
        assert!(
            matches!(err, MediaError::TooLarge { .. }),
            "{decoded_len} decoded bytes should exceed the {} byte budget, got {err:?}",
            config.max_bytes
        );
    }

    // One byte under the budget must pass the size gate and fail only on
    // format, proving the estimate does not over-reject.
    let just_under = b64(&vec![0u8; config.max_bytes - 1]);
    assert_eq!(
        probe(
            MediaRef::Inline {
                data: &just_under,
                declared_type: None,
            },
            &config,
        )
        .unwrap_err(),
        MediaError::UnsupportedFormat
    );

    // A small valid PNG must survive the estimate untouched: an over-eager
    // estimate would reject legitimate images long before their real size.
    let small = b64(&png_header(8, 8));
    let (bytes, probed) = probe(
        MediaRef::Inline {
            data: &small,
            declared_type: None,
        },
        &config,
    )
    .expect("a 29-byte PNG is comfortably inside a 1 KiB budget");
    assert_eq!(probed.byte_len, bytes.len());
    assert_eq!((probed.width, probed.height), (8, 8));
}

#[test]
fn pixel_budget_rejects_everything_above_the_limit() {
    // Same `>` versus `==` hazard on the decompression-bomb guard, which is
    // the one that actually protects memory.
    let config = MediaConfig {
        max_pixels: 10_000,
        ..MediaConfig::default()
    };
    for (w, h) in [(101, 100), (200, 100), (1000, 1000), (50_000, 50_000)] {
        let err = probe_bytes(&png_header(w, h), &config).unwrap_err();
        assert!(
            matches!(err, MediaError::TooManyPixels { .. }),
            "{w}x{h} should exceed the 10000 pixel budget, got {err:?}"
        );
    }
    assert!(probe_bytes(&png_header(100, 100), &config).is_ok());
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
fn matches_rejects_hashes_beyond_the_threshold() {
    // Without this, `matches` could return true unconditionally and every
    // test above would still pass: they only ever assert that similar images
    // stay close, never that dissimilar ones are refused.
    let base = PerceptualHash(0);
    assert!(base.matches(PerceptualHash(0)));

    // Exactly at the threshold matches; one bit further does not.
    let at = PerceptualHash((1u64 << MATCH_THRESHOLD) - 1);
    assert_eq!(base.distance(at), MATCH_THRESHOLD);
    assert!(base.matches(at));

    let over = PerceptualHash((1u64 << (MATCH_THRESHOLD + 1)) - 1);
    assert_eq!(base.distance(over), MATCH_THRESHOLD + 1);
    assert!(
        !base.matches(over),
        "one bit past the threshold must not match"
    );

    assert!(!base.matches(PerceptualHash(u64::MAX)));
}

#[test]
fn display_and_hex_agree_and_are_not_empty() {
    // Display is used in journals and diagnostics; an empty or default
    // rendering would silently erase provenance identifiers.
    for raw in [0u64, 1, 0xdead_beef, u64::MAX] {
        let h = PerceptualHash(raw);
        let shown = h.to_string();
        assert_eq!(shown, h.to_hex());
        assert_eq!(shown.len(), 16, "hash must render as 16 hex digits");
        assert_eq!(u64::from_str_radix(&shown, 16).expect("hex"), raw);
    }
}

#[test]
fn luma_conversion_weights_the_channels_correctly() {
    // Pins the BT.601 arithmetic and the stride over RGB triples: a wrong
    // stride reads the wrong channel, and wrong weights flatten the image.
    let gray = GrayImage::from_rgb(3, 1, &[255, 0, 0, 0, 255, 0, 0, 0, 255]).expect("rgb");
    // Red 0.299, green 0.587, blue 0.114 of 255.
    assert_eq!(gray.luma, vec![76, 150, 29]);

    // Neutral colours map to themselves regardless of weighting.
    let neutral = GrayImage::from_rgb(2, 1, &[0, 0, 0, 255, 255, 255]).expect("rgb");
    assert_eq!(neutral.luma, vec![0, 255]);

    // Pixel count must follow width * height, not width + height.
    assert!(GrayImage::from_rgb(3, 2, &[128; 18]).is_some());
    assert!(GrayImage::from_rgb(3, 2, &[128; 15]).is_none());
}

#[test]
fn images_smaller_than_the_grid_are_sampled_without_panicking() {
    // The 9x8 grid is larger than these images, so every cell samples past
    // the edge. Clamping must hold: an off-by-one in the bound would index
    // out of range, and folding the clamp differently would collapse
    // distinct images onto the same hash.
    let one = GrayImage::new(1, 1, vec![128]).expect("image");
    assert_eq!(gradient_hash(&one).0, 0, "a single pixel has no gradient");

    let two_by_one_dark_left = GrayImage::new(2, 1, vec![0, 255]).expect("image");
    let two_by_one_dark_right = GrayImage::new(2, 1, vec![255, 0]).expect("image");
    assert_ne!(
        gradient_hash(&two_by_one_dark_left),
        gradient_hash(&two_by_one_dark_right),
        "clamping must not collapse opposite gradients onto one hash"
    );

    // A range of sub-grid sizes, all of which must complete.
    for (w, h) in [(1, 1), (1, 8), (8, 1), (2, 3), (5, 5), (9, 8)] {
        let img = GrayImage::new(w, h, vec![64; (w * h) as usize]).expect("image");
        assert_eq!(gradient_hash(&img).0, 0);
    }
}

#[test]
fn hash_encodes_horizontal_gradients_not_a_constant() {
    // A flat image has no left-to-right differences, so every comparison bit
    // is zero. A gradient must produce a non-zero, direction-dependent hash.
    let flat = GrayImage::new(16, 16, vec![128; 256]).expect("image");
    assert_eq!(
        gradient_hash(&flat).0,
        0,
        "flat image must hash to all zeros"
    );

    let mut ramp = Vec::with_capacity(256);
    for _ in 0..16 {
        for x in 0..16u32 {
            ramp.push((x * 16) as u8);
        }
    }
    // A strictly rising ramp makes every "left brighter than right" test
    // false, so it also hashes to zero. That is correct, and it is the reason
    // the direction matters: reversing the ramp must invert every bit.
    let rising = GrayImage::new(16, 16, ramp.clone()).expect("image");
    assert_eq!(gradient_hash(&rising).0, 0);

    let falling_luma: Vec<u8> = ramp
        .chunks_exact(16)
        .flat_map(|row| row.iter().rev().copied())
        .collect();
    let falling = GrayImage::new(16, 16, falling_luma).expect("image");
    assert_eq!(
        gradient_hash(&falling).0,
        u64::MAX,
        "a strictly falling ramp must set every comparison bit"
    );
    assert_ne!(
        gradient_hash(&rising),
        gradient_hash(&falling),
        "opposite gradients must not collide"
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
    assert_eq!(replayed[0].phash.as_deref(), Some("00000000deadbeef"));
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
    assert_eq!(replayed[0].phash.as_deref(), Some("0000000000000001"));
}

#[test]
fn an_event_without_a_fingerprint_is_still_journaled() {
    // An image whose pixels could not be reached is exactly the kind of event
    // an operator wants afterwards. Recording it with the fingerprint absent
    // is honest; recording a placeholder would collide with every other
    // undecodable image.
    let dir = tempfile::tempdir().expect("tempdir");
    let mut journal = MediaJournal::open(dir.path()).expect("open journal");
    let probe = probe_bytes(&png_header(320, 200), &MediaConfig::default()).unwrap();

    journal
        .append(&MediaEvent::observed(&probe).with_tenant("acme"))
        .expect("append");

    let replayed = journal.replay_current().expect("replay");
    assert_eq!(replayed.len(), 1);
    assert_eq!(replayed[0].phash, None);
    assert_eq!(replayed[0].format, "image/png");
    assert_eq!((replayed[0].width, replayed[0].height), (320, 200));

    // The absent fingerprint must not appear as a null in the journal line.
    let line = serde_json::to_string(&replayed[0]).expect("serialise");
    assert!(
        !line.contains("phash"),
        "absent phash should be omitted: {line}"
    );
}

#[test]
fn replaying_an_absent_month_is_empty_not_an_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let journal = MediaJournal::open(dir.path()).expect("open journal");
    assert!(journal.replay("1999-01").expect("replay").is_empty());
}

// --- config --------------------------------------------------------------

#[test]
fn an_operator_can_enable_the_slice_from_toml() {
    // The point of this test: PRs 1 and 2 shipped these config structs, but
    // nothing referenced them from the top-level Config, so no TOML file
    // could reach them. A feature nobody can switch on is not shipped.
    let toml = r#"
[router]
default = "smart"

[media]
mode = "async"
max_bytes = 1048576
max_pixels = 5000000
fetch_remote = false

[media.sidecar.endpoints.ocr]
unix = { path = "/tmp/grob-ocr.sock" }
"#;
    let config: crate::config::AppConfig = toml::from_str(toml).expect("parse config");

    assert!(config.media.is_enabled());
    assert_eq!(config.media.max_bytes, 1_048_576);
    assert_eq!(config.media.max_pixels, 5_000_000);
    assert!(!config.media.fetch_remote);

    use super::sidecar::Capability;
    assert!(config.media.sidecar.is_enabled(Capability::Ocr));
    assert!(!config.media.sidecar.is_enabled(Capability::Watermark));
}

#[test]
fn an_absent_media_section_leaves_the_slice_off() {
    // Every existing deployment has no [media] section, and must keep
    // behaving exactly as before.
    let minimal = "[router]\ndefault = \"smart\"\n";
    let config: crate::config::AppConfig =
        toml::from_str(minimal).expect("parse config without a media section");
    assert!(!config.media.is_enabled());
    assert!(!config.media.fetch_remote);
    assert!(config.media.sidecar.endpoints.is_empty());
}

#[test]
fn slice_is_inert_by_default() {
    let config = MediaConfig::default();
    assert!(!config.is_enabled(), "media must be off unless asked for");
    assert!(!config.fetch_remote, "remote fetching is an SSRF primitive");
}

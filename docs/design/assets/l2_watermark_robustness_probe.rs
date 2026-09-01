//! Reproducible probe behind the L2 (invisible watermark) robustness figures in
//! `docs/design/001-image-dlp-provenance.md`. Kept as an asset, not compiled by the
//! workspace, so the numbers in the design doc can be re-derived rather than trusted.
//!
//! ```text
//! # models (~65 MB, not vendored)
//! mkdir -p /tmp/tm-models && cd /tmp/tm-models
//! for m in encoder_Q.onnx decoder_Q.onnx; do
//!   curl -sLO "https://cai-watermark.adobe.net/watermarking/trustmark-models/$m"
//! done
//! curl -sLO "https://raw.githubusercontent.com/adobe/trustmark/main/images/ghost.png"
//!
//! cargo new /tmp/probe-l2 && cd /tmp/probe-l2
//! cargo add trustmark image@0.25
//! cp <this file> src/main.rs
//! cargo run --release
//! ```
//!
//! The payload length is not free: `Version::data_bits()` fixes it (61 bits for Bch5).
//! Passing any other length fails with `InvalidDataLength`, which is exactly the
//! capacity budget a `trace_id` has to fit inside.

use image::{DynamicImage, GenericImageView, RgbImage};
use std::io::Cursor;
use trustmark::{Trustmark, Variant, Version};

/// Deterministic pseudo-screenshot, same generator as the pHash probe.
fn synth(seed: u32, w: u32, h: u32) -> DynamicImage {
    let mut img = RgbImage::new(w, h);
    for y in 0..h {
        for x in 0..w {
            let fx = x as f32 / w as f32;
            let fy = y as f32 / h as f32;
            let s = seed as f32 * 2.9;
            let f = 2.0 + (seed % 5) as f32 * 3.0;
            let r = ((fx * f + s).sin() * 90.0 + 128.0) as u8;
            let g = ((fy * (f * 0.6) + s * 1.7).cos() * 80.0 + 120.0) as u8;
            let b = (((fx * 1.7 - fy * 2.3) * f + s).sin() * 70.0 + 130.0) as u8;
            let n = (seed % 7) + 2;
            let boxed = ((x / (11 + seed * 5)) + (y / (7 + seed * 3))) % n == 0;
            img.put_pixel(
                x,
                y,
                image::Rgb(if boxed { [240, 240, 240] } else { [r, g, b] }),
            );
        }
    }
    DynamicImage::ImageRgb8(img)
}

fn jpeg(img: &DynamicImage, q: u8) -> DynamicImage {
    let mut buf = Cursor::new(Vec::new());
    img.to_rgb8()
        .write_with_encoder(image::codecs::jpeg::JpegEncoder::new_with_quality(
            &mut buf, q,
        ))
        .unwrap();
    image::load_from_memory(&buf.into_inner()).unwrap()
}

fn main() {
    let models = std::env::args().nth(1).unwrap_or("/tmp/tm-models".into());
    let tm = match Trustmark::new(&models, Variant::Q, Version::Bch5) {
        Ok(t) => t,
        Err(e) => {
            println!("cannot load models from {models}: {e:?}");
            return;
        }
    };

    let bits = Version::Bch5.data_bits() as usize;
    let payload: String = (0..bits)
        .map(|i| if i % 3 == 0 { '1' } else { '0' })
        .collect();
    println!("payload capacity (Bch5): {bits} bits");

    // Sanity first: does a clean roundtrip work at all, on which kind of image?
    let candidates: Vec<(&str, Option<DynamicImage>)> = vec![
        (
            "upstream ghost.png",
            image::open(format!("{models}/ghost.png")).ok(),
        ),
        ("synthetic 512x512", Some(synth(1, 512, 512))),
        ("synthetic 256x256", Some(synth(1, 256, 256))),
    ];

    let mut carrier: Option<(String, DynamicImage)> = None;
    println!("\nclean roundtrip by carrier:");
    for (label, img) in candidates {
        let Some(img) = img else {
            println!("  {label:<20} (missing)");
            continue;
        };
        let t = std::time::Instant::now();
        match tm.encode(payload.clone(), img.clone(), 0.95) {
            Ok(marked) => {
                let ms = t.elapsed().as_millis();
                let ok = tm.decode(marked.clone()).map(|s| s == payload).unwrap_or(false);
                println!("  {label:<20} {} ({ms} ms)", if ok { "OK" } else { "FAIL" });
                if ok && carrier.is_none() {
                    carrier = Some((label.to_string(), marked));
                }
            }
            Err(e) => println!("  {label:<20} encode error {e:?}"),
        }
    }

    let Some((label, marked)) = carrier else {
        println!("\nno carrier survived a clean roundtrip; robustness matrix is meaningless here");
        return;
    };
    println!("\nrobustness matrix (carrier: {label})");

    let (w, h) = marked.dimensions();
    let cases: Vec<(String, DynamicImage)> = vec![
        ("clean".into(), marked.clone()),
        ("jpeg q=90".into(), jpeg(&marked, 90)),
        ("jpeg q=70".into(), jpeg(&marked, 70)),
        ("jpeg q=50".into(), jpeg(&marked, 50)),
        ("jpeg q=30".into(), jpeg(&marked, 30)),
        (
            "resize 75%".into(),
            marked.resize_exact(w * 3 / 4, h * 3 / 4, image::imageops::FilterType::Lanczos3),
        ),
        (
            "resize 50%".into(),
            marked.resize_exact(w / 2, h / 2, image::imageops::FilterType::Lanczos3),
        ),
        (
            "resize 25%".into(),
            marked.resize_exact(w / 4, h / 4, image::imageops::FilterType::Lanczos3),
        ),
        (
            "crop 10%".into(),
            marked.crop_imm(w / 20, h / 20, w * 9 / 10, h * 9 / 10),
        ),
        (
            "crop 25%".into(),
            marked.crop_imm(w / 8, h / 8, w * 3 / 4, h * 3 / 4),
        ),
        ("grayscale".into(), marked.grayscale()),
        ("hflip".into(), marked.fliph()),
        ("rot90".into(), marked.rotate90()),
        ("brighten +2".into(), marked.brighten(2)),
        ("brighten +5".into(), marked.brighten(5)),
        ("brighten +8".into(), marked.brighten(8)),
        ("brighten +12".into(), marked.brighten(12)),
        ("darken -5".into(), marked.brighten(-5)),
        ("contrast +10".into(), marked.adjust_contrast(10.0)),
        ("jpeg q=60".into(), jpeg(&marked, 60)),
        (
            "resize50 + jpeg60".into(),
            jpeg(&marked.resize_exact(w / 2, h / 2, image::imageops::FilterType::Lanczos3), 60),
        ),
        ("vflip".into(), marked.flipv()),
        ("crop 15%".into(), marked.crop_imm(w*3/40, h*3/40, w*17/20, h*17/20)),
        ("crop 20%".into(), marked.crop_imm(w/10, h/10, w*8/10, h*8/10)),
        (
            "resize50+bright+jpeg60".into(),
            jpeg(
                &marked
                    .resize_exact(w / 2, h / 2, image::imageops::FilterType::Lanczos3)
                    .brighten(12),
                60,
            ),
        ),
    ];

    println!("{:<26} extracted", "transform");
    println!("{}", "-".repeat(40));
    for (name, img) in cases {
        let ok = tm.decode(img).map(|s| s == payload).unwrap_or(false);
        println!("{name:<26} {}", if ok { "YES" } else { "no" });
    }
}

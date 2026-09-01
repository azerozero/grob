//! Reproducible probe behind the L3 (perceptual fingerprint) robustness figures in
//! `docs/design/001-image-dlp-provenance.md`. Kept as an asset, not compiled by the
//! workspace, so the numbers in the design doc can be re-derived rather than trusted.
//!
//! ```text
//! cargo new /tmp/probe-ph && cd /tmp/probe-ph
//! cargo add img_hash image@0.23
//! cp <this file> src/main.rs
//! cargo run --release
//! ```
//!
//! Note on method: an earlier corpus made every "different" image land at distance 1,
//! which produced a false "no separation" verdict. The probe therefore asserts the
//! separation between same-image and different-image distances before any robustness
//! claim is drawn from it.

use image::{DynamicImage, GenericImageView, ImageOutputFormat, RgbImage};
use img_hash::{HashAlg, HasherConfig};
use std::io::Cursor;

/// Deterministic pseudo-photo: smooth gradients + shapes, closer to a real
/// screenshot than random noise (random noise is unfairly easy for pHash).
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
    img.write_to(&mut buf, ImageOutputFormat::Jpeg(q)).unwrap();
    image::load_from_memory(&buf.into_inner()).unwrap()
}

fn main() {
    let hasher = HasherConfig::new().hash_alg(HashAlg::Gradient).to_hasher();
    let base = synth(1, 800, 600);
    let h0 = hasher.hash_image(&base);

    println!("transform                       hamming(/64)");
    println!("----------------------------------------------");

    let mut rows: Vec<(String, u32)> = Vec::new();
    for q in [90u8, 70, 50, 30] {
        rows.push((format!("jpeg q={q}"), h0.dist(&hasher.hash_image(&jpeg(&base, q)))));
    }
    for pct in [75u32, 50, 25] {
        let (w, h) = base.dimensions();
        let r = base.resize_exact(w * pct / 100, h * pct / 100, image::imageops::FilterType::Lanczos3);
        rows.push((format!("resize {pct}%"), h0.dist(&hasher.hash_image(&r))));
    }
    for pct in [5u32, 10, 25] {
        let (w, h) = base.dimensions();
        let (dx, dy) = (w * pct / 200, h * pct / 200);
        let c = base.crop_imm(dx, dy, w - dx * 2, h - dy * 2);
        rows.push((format!("crop {pct}%"), h0.dist(&hasher.hash_image(&c))));
    }
    // "screenshot": resize + jpeg + slight brightness shift
    let shot = jpeg(&base.resize_exact(1024, 768, image::imageops::FilterType::Triangle).brighten(8), 80);
    rows.push(("screenshot-ish".into(), h0.dist(&hasher.hash_image(&shot))));
    rows.push(("grayscale".into(), h0.dist(&hasher.hash_image(&base.grayscale()))));
    // Chained/adversarial: what actually happens in the wild.
    let chain = jpeg(
        &base
            .resize_exact(400, 300, image::imageops::FilterType::Lanczos3)
            .brighten(12),
        60,
    );
    rows.push(("resize50+bright+jpeg60".into(), h0.dist(&hasher.hash_image(&chain))));
    let (w, h) = base.dimensions();
    let hard = jpeg(&base.crop_imm(w / 10, h / 10, w * 8 / 10, h * 8 / 10), 60);
    rows.push(("crop20%+jpeg60".into(), h0.dist(&hasher.hash_image(&hard))));
    let flip = base.fliph();
    rows.push(("hflip (expected FAIL)".into(), h0.dist(&hasher.hash_image(&flip))));
    let rot = base.rotate90();
    rows.push(("rot90 (expected FAIL)".into(), h0.dist(&hasher.hash_image(&rot))));

    for (name, d) in &rows {
        println!("{name:<30}  {d:>2}");
    }

    // Discrimination: distance between genuinely different images.
    let others: Vec<u32> = (2..12)
        .map(|s| h0.dist(&hasher.hash_image(&synth(s, 800, 600))))
        .collect();
    let min_other = *others.iter().min().unwrap();
    let max_same = rows
        .iter()
        .filter(|(n, _)| !n.contains("FAIL"))
        .map(|(_, d)| *d)
        .max()
        .unwrap();

    println!("\nworst same-image distance : {max_same}");
    println!("closest different image   : {min_other}");
    println!(
        "separation                : {}",
        if min_other > max_same {
            format!("OK, gap of {}", min_other - max_same)
        } else {
            "NONE - overlapping, L3 unusable as specified".into()
        }
    );
}

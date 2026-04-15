//! Trace log management commands.

use anyhow::{Context, Result};
use base64::Engine;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

/// Decrypts and displays encrypted trace entries.
pub fn cmd_logs_decrypt(path: Option<PathBuf>, output: Option<PathBuf>) -> Result<()> {
    let trace_path = path.unwrap_or_else(|| {
        let default = crate::storage::GrobStore::default_path();
        default
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("trace.jsonl")
    });

    if !trace_path.exists() {
        anyhow::bail!("Trace file not found: {}", trace_path.display());
    }

    let cipher = crate::storage::encrypt::StorageCipher::load_or_generate(
        &crate::storage::GrobStore::default_path(),
    )
    .context("Failed to load encryption key")?;

    let reader: Box<dyn BufRead> = if trace_path.extension().is_some_and(|ext| ext == "zst") {
        let file = std::fs::File::open(&trace_path)
            .with_context(|| format!("Failed to open: {}", trace_path.display()))?;
        let decoder = zstd::Decoder::new(file).context("Failed to initialize zstd decoder")?;
        Box::new(BufReader::new(decoder))
    } else {
        let file = std::fs::File::open(&trace_path)
            .with_context(|| format!("Failed to open: {}", trace_path.display()))?;
        Box::new(BufReader::new(file))
    };

    let mut writer: Box<dyn Write> = if let Some(ref out_path) = output {
        Box::new(
            std::fs::File::create(out_path)
                .with_context(|| format!("Failed to create: {}", out_path.display()))?,
        )
    } else {
        Box::new(std::io::stdout().lock())
    };

    let b64 = base64::engine::general_purpose::STANDARD;
    let mut decrypted_count = 0u64;
    let mut plaintext_count = 0u64;

    for line_result in reader.lines() {
        let line = line_result.context("Failed to read line")?;
        if line.is_empty() {
            continue;
        }

        let decrypted = if let Ok(bytes) = b64.decode(&line) {
            match cipher.decrypt(&bytes) {
                Ok(plain) => {
                    decrypted_count += 1;
                    String::from_utf8(plain).unwrap_or_else(|_| line.clone())
                }
                Err(_) => {
                    plaintext_count += 1;
                    line
                }
            }
        } else {
            plaintext_count += 1;
            line
        };

        writeln!(writer, "{decrypted}").context("Failed to write output")?;
    }

    if output.is_some() {
        eprintln!(
            "Decrypted {decrypted_count} entries, {plaintext_count} plaintext (total {})",
            decrypted_count + plaintext_count
        );
    }

    Ok(())
}

//! Message tracing for debugging
//!
//! Logs full request/response messages to a JSONL file with size-based rotation,
//! optional zstd compression of rotated files, and optional AES-256-GCM encryption.

use crate::cli::TracingConfig;
use crate::models::{CanonicalRequest, RouteType};
use crate::providers::ProviderResponse;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use uuid::Uuid;

/// Message tracer that writes to JSONL file with rotation support.
pub struct MessageTracer {
    config: TracingConfig,
    /// Expanded absolute path to the trace file.
    trace_path: PathBuf,
    file: Option<Mutex<File>>,
    cipher: Option<crate::storage::encrypt::StorageCipher>,
}

/// A trace entry for a request
#[derive(Serialize)]
struct RequestTrace {
    ts: DateTime<Utc>,
    dir: &'static str,
    id: String,
    model: String,
    provider: String,
    route_type: String,
    is_stream: bool,
    tool_count: usize,
    messages: serde_json::Value,
}

/// A trace entry for a response
#[derive(Serialize)]
struct ResponseTrace {
    ts: DateTime<Utc>,
    dir: &'static str,
    id: String,
    latency_ms: u64,
    stop_reason: String,
    input_tokens: u32,
    output_tokens: u32,
    content: serde_json::Value,
}

/// A trace entry for an error
#[derive(Serialize)]
struct ErrorTrace {
    ts: DateTime<Utc>,
    dir: &'static str,
    id: String,
    error: String,
}

impl MessageTracer {
    /// Creates a new tracer from config.
    pub fn new(config: TracingConfig) -> Self {
        let trace_path = expand_tilde(&config.path);

        if !config.enabled {
            return Self {
                config,
                trace_path,
                file: None,
                cipher: None,
            };
        }

        let cipher = if config.encrypt {
            match crate::storage::encrypt::StorageCipher::load_or_generate(
                &crate::storage::GrobStore::default_path(),
            ) {
                Ok(c) => {
                    tracing::info!("Trace encryption enabled (AES-256-GCM)");
                    Some(c)
                }
                Err(e) => {
                    tracing::error!("Failed to initialize trace encryption: {e}");
                    None
                }
            }
        } else {
            None
        };

        // Ensure parent directory exists
        if let Some(parent) = trace_path.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                tracing::error!("Failed to create tracing directory: {}", e);
                return Self {
                    config,
                    trace_path,
                    file: None,
                    cipher: None,
                };
            }
        }

        // Open file for appending
        match open_append(&trace_path) {
            Ok(file) => {
                tracing::info!("Message tracing enabled: {}", trace_path.display());
                Self {
                    config,
                    trace_path,
                    file: Some(Mutex::new(file)),
                    cipher,
                }
            }
            Err(e) => {
                tracing::error!("Failed to open trace file: {}", e);
                Self {
                    config,
                    trace_path,
                    file: None,
                    cipher: None,
                }
            }
        }
    }

    /// Generates a new trace ID.
    pub fn new_trace_id(&self) -> String {
        if self.file.is_some() {
            Uuid::new_v4().to_string()[..8].to_string()
        } else {
            String::new()
        }
    }

    /// Traces an incoming request.
    pub fn trace_request(
        &self,
        id: &str,
        request: &CanonicalRequest,
        provider: &str,
        route_type: &RouteType,
        is_stream: bool,
    ) {
        let Some(ref file_mutex) = self.file else {
            return;
        };

        // Build messages JSON, optionally omitting system prompt
        let messages = if self.config.omit_system_prompt {
            let mut req_clone = request.clone();
            req_clone.system = None;
            serde_json::to_value(&req_clone.messages).unwrap_or_default()
        } else {
            serde_json::to_value(&request.messages).unwrap_or_default()
        };

        let trace = RequestTrace {
            ts: Utc::now(),
            dir: "req",
            id: id.to_string(),
            model: request.model.clone(),
            provider: provider.to_string(),
            route_type: route_type.to_string(),
            is_stream,
            tool_count: request.tools.as_ref().map_or(0, |t| t.len()),
            messages,
        };

        self.write_trace(&trace, file_mutex);
    }

    /// Traces a response.
    pub fn trace_response(&self, id: &str, response: &ProviderResponse, latency_ms: u64) {
        let Some(ref file_mutex) = self.file else {
            return;
        };

        let trace = ResponseTrace {
            ts: Utc::now(),
            dir: "res",
            id: id.to_string(),
            latency_ms,
            stop_reason: response.stop_reason.clone().unwrap_or_default(),
            input_tokens: response.usage.input_tokens,
            output_tokens: response.usage.output_tokens,
            content: serde_json::to_value(&response.content).unwrap_or_default(),
        };

        self.write_trace(&trace, file_mutex);
    }

    /// Traces an error.
    pub fn trace_error(&self, id: &str, error: &str) {
        let Some(ref file_mutex) = self.file else {
            return;
        };

        let trace = ErrorTrace {
            ts: Utc::now(),
            dir: "err",
            id: id.to_string(),
            error: error.to_string(),
        };

        self.write_trace(&trace, file_mutex);
    }

    fn write_trace<T: Serialize>(&self, trace: &T, file_mutex: &Mutex<File>) {
        let Ok(json) = serde_json::to_string(trace) else {
            return;
        };

        let Ok(mut file) = file_mutex.lock() else {
            return;
        };

        // Check size before writing; rotate if over limit
        let max_bytes = self.config.max_size_mb * 1024 * 1024;
        if max_bytes > 0 {
            if let Ok(meta) = file.metadata() {
                if meta.len() >= max_bytes {
                    if let Ok(new_file) = rotate_file(
                        &self.trace_path,
                        self.config.max_files,
                        self.config.compress,
                    ) {
                        *file = new_file;
                    }
                }
            }
        }

        let line = if let Some(ref cipher) = self.cipher {
            match cipher.encrypt(json.as_bytes()) {
                Ok(encrypted) => {
                    use base64::Engine;
                    base64::engine::general_purpose::STANDARD.encode(&encrypted)
                }
                Err(e) => {
                    tracing::error!("Trace encryption failed: {e}");
                    return;
                }
            }
        } else {
            json
        };
        let _ = writeln!(file, "{}", line);
    }
}

// ── Trait implementation ──

impl crate::traits::Tracer for MessageTracer {
    fn new_trace_id(&self) -> String {
        self.new_trace_id()
    }

    fn trace_request(
        &self,
        id: &str,
        request: &CanonicalRequest,
        provider: &str,
        route_type: &RouteType,
        is_stream: bool,
    ) {
        self.trace_request(id, request, provider, route_type, is_stream);
    }

    fn trace_response(
        &self,
        id: &str,
        response: &crate::providers::ProviderResponse,
        latency_ms: u64,
    ) {
        self.trace_response(id, response, latency_ms);
    }

    fn trace_error(&self, id: &str, error: &str) {
        self.trace_error(id, error);
    }
}

// ── File helpers ──

/// Opens a file for appending, creating it if needed.
fn open_append(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

/// Rotates trace files and returns a fresh file handle for the main path.
///
/// Naming scheme: `trace.jsonl` -> `trace.1.jsonl` (or `.1.jsonl.zst`),
/// `trace.1.jsonl` -> `trace.2.jsonl`, etc.
fn rotate_file(base: &Path, max_files: usize, compress: bool) -> std::io::Result<File> {
    // Delete the oldest if it exists
    let oldest = rotated_path(base, max_files, compress);
    if oldest.exists() {
        fs::remove_file(&oldest)?;
    }

    // Shift existing rotated files up by one
    for i in (1..max_files).rev() {
        let src = rotated_path(base, i, compress);
        let dst = rotated_path(base, i + 1, compress);
        if src.exists() {
            fs::rename(&src, &dst)?;
        }
    }

    // Move current file to slot 1
    let slot1 = rotated_path(base, 1, compress);
    if base.exists() {
        if compress {
            compress_to_zstd(base, &slot1)?;
            fs::remove_file(base)?;
        } else {
            fs::rename(base, &slot1)?;
        }
    }

    open_append(base)
}

/// Builds the path for a rotated file at a given index.
///
/// For `trace.jsonl` with index 2: `trace.2.jsonl` (or `trace.2.jsonl.zst`).
fn rotated_path(base: &Path, index: usize, compressed: bool) -> PathBuf {
    let stem = base
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let ext = base
        .extension()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let parent = base.parent().unwrap_or(base);
    let name = if compressed {
        format!("{stem}.{index}.{ext}.zst")
    } else {
        format!("{stem}.{index}.{ext}")
    };
    parent.join(name)
}

/// Compresses a file to zstd format.
fn compress_to_zstd(src: &Path, dst: &Path) -> std::io::Result<()> {
    let input = std::fs::File::open(src)?;
    let output = std::fs::File::create(dst)?;
    let mut encoder = zstd::Encoder::new(output, 3)?;
    std::io::copy(&mut std::io::BufReader::new(input), &mut encoder)?;
    encoder.finish()?;
    Ok(())
}

/// Expands ~ to home directory.
fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = crate::home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn make_config(
        dir: &Path,
        max_size_mb: u64,
        max_files: usize,
        compress: bool,
    ) -> TracingConfig {
        TracingConfig {
            enabled: true,
            path: dir.join("trace.jsonl").to_string_lossy().to_string(),
            omit_system_prompt: true,
            max_size_mb,
            max_files,
            compress,
            encrypt: false,
        }
    }

    #[test]
    fn rotation_triggers_when_file_exceeds_max_size() {
        let tmp = tempfile::tempdir().unwrap();
        let trace_path = tmp.path().join("trace.jsonl");

        {
            let mut f = File::create(&trace_path).unwrap();
            writeln!(f, "{}", "x".repeat(100)).unwrap();
        }

        let new_file = rotate_file(&trace_path, 3, false).unwrap();
        drop(new_file);

        let meta = fs::metadata(&trace_path).unwrap();
        assert_eq!(meta.len(), 0);

        let rotated = rotated_path(&trace_path, 1, false);
        assert!(rotated.exists(), "rotated file at slot 1 should exist");
    }

    #[test]
    fn rotation_shifts_existing_files() {
        let tmp = tempfile::tempdir().unwrap();
        let trace_path = tmp.path().join("trace.jsonl");

        fs::write(rotated_path(&trace_path, 1, false), "old-1").unwrap();
        fs::write(rotated_path(&trace_path, 2, false), "old-2").unwrap();
        fs::write(&trace_path, "current").unwrap();

        let new_file = rotate_file(&trace_path, 3, false).unwrap();
        drop(new_file);

        assert_eq!(
            fs::read_to_string(rotated_path(&trace_path, 3, false)).unwrap(),
            "old-2"
        );
        assert_eq!(
            fs::read_to_string(rotated_path(&trace_path, 2, false)).unwrap(),
            "old-1"
        );
        assert_eq!(
            fs::read_to_string(rotated_path(&trace_path, 1, false)).unwrap(),
            "current"
        );
        assert_eq!(fs::metadata(&trace_path).unwrap().len(), 0);
    }

    #[test]
    fn rotation_deletes_oldest_beyond_max_files() {
        let tmp = tempfile::tempdir().unwrap();
        let trace_path = tmp.path().join("trace.jsonl");

        fs::write(rotated_path(&trace_path, 1, false), "old-1").unwrap();
        fs::write(rotated_path(&trace_path, 2, false), "old-2-should-die").unwrap();
        fs::write(&trace_path, "current").unwrap();

        let new_file = rotate_file(&trace_path, 2, false).unwrap();
        drop(new_file);

        assert_eq!(
            fs::read_to_string(rotated_path(&trace_path, 2, false)).unwrap(),
            "old-1"
        );
        assert_eq!(
            fs::read_to_string(rotated_path(&trace_path, 1, false)).unwrap(),
            "current"
        );
    }

    #[test]
    fn rotation_compresses_with_zstd() {
        let tmp = tempfile::tempdir().unwrap();
        let trace_path = tmp.path().join("trace.jsonl");
        let payload = "hello zstd compression test payload";
        fs::write(&trace_path, payload).unwrap();

        let new_file = rotate_file(&trace_path, 3, true).unwrap();
        drop(new_file);

        let compressed_path = rotated_path(&trace_path, 1, true);
        assert!(
            compressed_path.exists(),
            "compressed rotated file should exist"
        );
        assert!(compressed_path.to_string_lossy().ends_with(".zst"));

        let compressed_data = fs::read(&compressed_path).unwrap();
        let decompressed = zstd::decode_all(compressed_data.as_slice()).unwrap();
        assert_eq!(String::from_utf8(decompressed).unwrap(), payload);

        assert_eq!(fs::metadata(&trace_path).unwrap().len(), 0);
    }

    #[test]
    fn rotated_path_naming() {
        let base = PathBuf::from("/tmp/trace.jsonl");
        assert_eq!(
            rotated_path(&base, 1, false),
            PathBuf::from("/tmp/trace.1.jsonl")
        );
        assert_eq!(
            rotated_path(&base, 3, true),
            PathBuf::from("/tmp/trace.3.jsonl.zst")
        );
    }

    #[test]
    fn tracer_write_triggers_rotation() {
        let tmp = tempfile::tempdir().unwrap();
        let trace_path = tmp.path().join("trace.jsonl");

        // Pre-fill the file to simulate near-limit (just over 1 MB)
        {
            let mut f = File::create(&trace_path).unwrap();
            let big_line = "x".repeat(1024 * 1024 + 1);
            write!(f, "{}", big_line).unwrap();
        }

        let config = make_config(tmp.path(), 1, 3, false);
        let tracer = MessageTracer::new(config);

        #[derive(Serialize)]
        struct Dummy {
            msg: String,
        }
        let dummy = Dummy {
            msg: "test".to_string(),
        };
        if let Some(ref fm) = tracer.file {
            tracer.write_trace(&dummy, fm);
        }

        let slot1 = rotated_path(&trace_path, 1, false);
        assert!(slot1.exists(), "rotation should have created slot 1 file");

        let current_size = fs::metadata(&trace_path).unwrap().len();
        assert!(
            current_size < 1024,
            "current file should be small after rotation, got {current_size}"
        );
    }
}

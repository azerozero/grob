//! Append-only JSONL journal of media observations.
//!
//! Same shape as the spend journal: one self-contained JSON object per line,
//! one file per month, written with `O_APPEND`. A truncated tail (a crash
//! mid-write) costs exactly one record, never the file.
//!
//! Records carry a fingerprint and shape only. No pixels, no OCR text, no
//! payload: a forensic journal that leaks what it was meant to protect would
//! defeat its own purpose.

use super::decode::MediaProbe;
use super::phash::PerceptualHash;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

/// One observed media item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaEvent {
    /// RFC-3339 observation timestamp.
    pub ts: String,
    /// Perceptual fingerprint, lowercase hex.
    pub phash: String,
    /// Sniffed MIME type.
    pub format: String,
    /// Declared width in pixels.
    pub width: u32,
    /// Declared height in pixels.
    pub height: u32,
    /// Encoded payload size in bytes.
    pub bytes: usize,
    /// Owning tenant, when the request carried one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// Model the request was routed to, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

impl MediaEvent {
    /// Builds an event from a probe and its fingerprint.
    #[must_use]
    pub fn new(probe: &MediaProbe, phash: PerceptualHash) -> Self {
        Self {
            ts: chrono::Utc::now().to_rfc3339(),
            phash: phash.to_hex(),
            format: probe.format.mime().to_string(),
            width: probe.width,
            height: probe.height,
            bytes: probe.byte_len,
            tenant: None,
            model: None,
        }
    }

    /// Attaches the owning tenant.
    #[must_use]
    pub fn with_tenant(mut self, tenant: impl Into<String>) -> Self {
        self.tenant = Some(tenant.into());
        self
    }

    /// Attaches the routed model.
    #[must_use]
    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = Some(model.into());
        self
    }
}

/// Append-only journal at `<base>/media/YYYY-MM.jsonl`.
#[derive(Debug)]
pub struct MediaJournal {
    dir: PathBuf,
    file: Option<File>,
    month: String,
}

impl MediaJournal {
    /// Opens (creating if needed) the journal under `base_dir`.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory or the current month's file cannot
    /// be created or opened for append.
    pub fn open(base_dir: &Path) -> Result<Self> {
        let dir = base_dir.join("media");
        fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create media dir: {}", dir.display()))?;
        let month = current_month();
        let file = Self::open_month(&dir, &month)?;
        Ok(Self {
            dir,
            file: Some(file),
            month,
        })
    }

    /// Opens one month's file for append.
    fn open_month(dir: &Path, month: &str) -> Result<File> {
        let path = dir.join(format!("{month}.jsonl"));
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("failed to open media journal: {}", path.display()))
    }

    /// Appends one event, rolling over when the month changes.
    ///
    /// # Errors
    ///
    /// Returns an error if the record cannot be serialised or written.
    pub fn append(&mut self, event: &MediaEvent) -> Result<()> {
        let month = current_month();
        if month != self.month {
            self.file = Some(Self::open_month(&self.dir, &month)?);
            self.month = month;
        }
        let Some(file) = self.file.as_mut() else {
            return Ok(());
        };
        let line = serde_json::to_string(event).context("failed to serialise media event")?;
        writeln!(file, "{line}").context("failed to append to media journal")?;
        Ok(())
    }

    /// Replays every record for `month`.
    ///
    /// Unparseable lines are skipped rather than fatal: a torn tail from a
    /// crash must not make the whole journal unreadable.
    ///
    /// # Errors
    ///
    /// Returns an error only if an existing file cannot be read. A missing
    /// file yields an empty list.
    pub fn replay(&self, month: &str) -> Result<Vec<MediaEvent>> {
        let path = self.dir.join(format!("{month}.jsonl"));
        if !path.exists() {
            return Ok(Vec::new());
        }
        let file = File::open(&path)
            .with_context(|| format!("failed to read media journal: {}", path.display()))?;
        Ok(BufReader::new(file)
            .lines()
            .map_while(Result::ok)
            .filter_map(|line| serde_json::from_str(&line).ok())
            .collect())
    }

    /// Replays the current month.
    ///
    /// # Errors
    ///
    /// See [`Self::replay`].
    pub fn replay_current(&self) -> Result<Vec<MediaEvent>> {
        self.replay(&current_month())
    }
}

/// Current month as `YYYY-MM`.
#[must_use]
pub fn current_month() -> String {
    chrono::Utc::now().format("%Y-%m").to_string()
}

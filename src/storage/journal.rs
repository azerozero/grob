//! Append-only JSONL spend journal.
//!
//! Each spend event is a self-contained JSON line in `spend/YYYY-MM.jsonl`.
//! Replayed at startup to rebuild [`SpendData`] in-memory.

use crate::features::token_pricing::spend::SpendData;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

/// Single spend event written as one JSONL line.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct SpendEvent {
    pub ts: String,
    pub kind: String,
    pub provider: String,
    pub model: String,
    pub cost_usd: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
}

/// Append-only JSONL spend journal.
pub(crate) struct SpendJournal {
    spend_dir: PathBuf,
    current_file: Option<File>,
    current_month: String,
}

impl SpendJournal {
    /// Opens or creates the spend journal directory.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be created.
    pub fn open(base_dir: &Path) -> Result<Self> {
        let spend_dir = base_dir.join("spend");
        fs::create_dir_all(&spend_dir)
            .with_context(|| format!("failed to create spend dir: {}", spend_dir.display()))?;

        let month = crate::features::token_pricing::spend::current_month();
        let file = Self::open_month_file(&spend_dir, &month)?;

        Ok(Self {
            spend_dir,
            current_file: Some(file),
            current_month: month,
        })
    }

    /// Appends a spend event to the current month's journal.
    pub fn append(&mut self, event: &SpendEvent) -> Result<()> {
        let month = crate::features::token_pricing::spend::current_month();
        if month != self.current_month {
            self.seal_current()?;
            self.current_month = month;
            self.current_file = Some(Self::open_month_file(&self.spend_dir, &self.current_month)?);
        }

        let file = self
            .current_file
            .as_mut()
            .context("journal file not open")?;
        let mut line = serde_json::to_vec(event)?;
        line.push(b'\n');
        file.write_all(&line)?;
        Ok(())
    }

    /// Flushes pending writes to disk.
    pub fn fsync(&mut self) -> Result<()> {
        if let Some(ref file) = self.current_file {
            file.sync_all().context("journal fsync failed")?;
        }
        Ok(())
    }

    /// Replays the current month's journal into a [`SpendData`].
    pub fn replay_current(&self) -> SpendData {
        let month = &self.current_month;
        let path = self.month_path(month);
        Self::replay_file(&path, month)
    }

    /// Replays a specific month's journal for tenant data.
    pub fn replay_for_tenant(&self, tenant: &str) -> SpendData {
        let month = &self.current_month;
        let path = self.month_path(month);
        Self::replay_file_for_tenant(&path, month, tenant)
    }

    fn month_path(&self, month: &str) -> PathBuf {
        self.spend_dir.join(format!("{month}.jsonl"))
    }

    fn replay_file(path: &Path, _expected_month: &str) -> SpendData {
        let file = match File::open(path) {
            Ok(f) => f,
            Err(_) => return SpendData::default(),
        };
        let reader = BufReader::new(file);
        let mut data = SpendData::default();

        for line in reader.lines() {
            let Ok(line) = line else { continue };
            if line.is_empty() {
                continue;
            }
            let Ok(event) = serde_json::from_str::<SpendEvent>(&line) else {
                tracing::warn!(line = %line, "skipping malformed journal line");
                continue;
            };
            // Skip tenant-scoped events for global replay.
            if event.tenant.is_some() {
                continue;
            }
            data.total += event.cost_usd;
            *data.by_provider.entry(event.provider.clone()).or_default() += event.cost_usd;
            *data.by_model.entry(event.model.clone()).or_default() += event.cost_usd;
            *data.by_provider_count.entry(event.provider).or_default() += 1;
        }
        data
    }

    fn replay_file_for_tenant(path: &Path, _expected_month: &str, tenant: &str) -> SpendData {
        let file = match File::open(path) {
            Ok(f) => f,
            Err(_) => return SpendData::default(),
        };
        let reader = BufReader::new(file);
        let mut data = SpendData::default();

        for line in reader.lines() {
            let Ok(line) = line else { continue };
            if line.is_empty() {
                continue;
            }
            let Ok(event) = serde_json::from_str::<SpendEvent>(&line) else {
                continue;
            };
            if event.tenant.as_deref() != Some(tenant) {
                continue;
            }
            data.total += event.cost_usd;
            *data.by_provider.entry(event.provider.clone()).or_default() += event.cost_usd;
            *data.by_model.entry(event.model.clone()).or_default() += event.cost_usd;
            *data.by_provider_count.entry(event.provider).or_default() += 1;
        }
        data
    }

    fn seal_current(&mut self) -> Result<()> {
        if let Some(ref file) = self.current_file {
            file.sync_all()?;
        }
        self.current_file = None;

        let current_path = self.month_path(&self.current_month);
        if current_path.exists() {
            let sealed = current_path.with_extension("jsonl.sealed");
            fs::rename(&current_path, &sealed)
                .with_context(|| format!("failed to seal journal {}", current_path.display()))?;
            tracing::info!(month = %self.current_month, "sealed spend journal");
        }
        Ok(())
    }

    fn open_month_file(spend_dir: &Path, month: &str) -> Result<File> {
        let path = spend_dir.join(format!("{month}.jsonl"));
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("failed to open journal: {}", path.display()))?;
        Ok(file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_and_replay() {
        let dir = tempfile::tempdir().unwrap();
        let mut journal = SpendJournal::open(dir.path()).unwrap();

        journal
            .append(&SpendEvent {
                ts: "2026-04-13T10:00:00Z".to_string(),
                kind: "spend".to_string(),
                provider: "anthropic".to_string(),
                model: "claude-opus".to_string(),
                cost_usd: 0.05,
                tenant: None,
            })
            .unwrap();

        journal
            .append(&SpendEvent {
                ts: "2026-04-13T10:01:00Z".to_string(),
                kind: "spend".to_string(),
                provider: "openai".to_string(),
                model: "gpt-4o".to_string(),
                cost_usd: 0.10,
                tenant: None,
            })
            .unwrap();

        journal.fsync().unwrap();

        let data = journal.replay_current();
        assert!((data.total - 0.15).abs() < 0.001);
        assert!((data.by_provider["anthropic"] - 0.05).abs() < 0.001);
        assert!((data.by_provider["openai"] - 0.10).abs() < 0.001);
        assert_eq!(data.by_provider_count["anthropic"], 1);
    }

    #[test]
    fn tenant_events_excluded_from_global() {
        let dir = tempfile::tempdir().unwrap();
        let mut journal = SpendJournal::open(dir.path()).unwrap();

        journal
            .append(&SpendEvent {
                ts: "2026-04-13T10:00:00Z".to_string(),
                kind: "spend".to_string(),
                provider: "anthropic".to_string(),
                model: "claude-opus".to_string(),
                cost_usd: 1.0,
                tenant: None,
            })
            .unwrap();
        journal
            .append(&SpendEvent {
                ts: "2026-04-13T10:01:00Z".to_string(),
                kind: "spend".to_string(),
                provider: "anthropic".to_string(),
                model: "claude-opus".to_string(),
                cost_usd: 2.0,
                tenant: Some("tenant-a".to_string()),
            })
            .unwrap();
        journal.fsync().unwrap();

        let global = journal.replay_current();
        assert!((global.total - 1.0).abs() < 0.001);

        let tenant = journal.replay_for_tenant("tenant-a");
        assert!((tenant.total - 2.0).abs() < 0.001);
    }

    #[test]
    fn malformed_lines_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let spend_dir = dir.path().join("spend");
        fs::create_dir_all(&spend_dir).unwrap();

        let month = crate::features::token_pricing::spend::current_month();
        let path = spend_dir.join(format!("{month}.jsonl"));
        fs::write(&path, "{\"ts\":\"t\",\"kind\":\"spend\",\"provider\":\"a\",\"model\":\"b\",\"cost_usd\":1.0}\n{broken\n{\"ts\":\"t\",\"kind\":\"spend\",\"provider\":\"c\",\"model\":\"d\",\"cost_usd\":2.0}\n").unwrap();

        let journal = SpendJournal::open(dir.path()).unwrap();
        let data = journal.replay_current();
        assert!((data.total - 3.0).abs() < 0.001);
    }

    #[test]
    fn empty_journal_replays_to_default() {
        let dir = tempfile::tempdir().unwrap();
        let journal = SpendJournal::open(dir.path()).unwrap();
        let data = journal.replay_current();
        assert_eq!(data.total, 0.0);
    }
}

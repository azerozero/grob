//! Append-only JSONL spend journal.
//!
//! Each spend event is a self-contained JSON line in `spend/YYYY-MM.jsonl`.
//! Replayed at startup to rebuild [`SpendData`] in-memory.

use crate::features::token_pricing::spend::SpendData;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
    /// Agent that incurred the spend, when one identified itself.
    ///
    /// Optional and omitted when absent, so existing journals stay readable
    /// and existing exports keep parsing unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
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
        Self::open_in(&spend_dir)
    }

    /// Opens or creates a spend journal at an explicit directory path.
    ///
    /// Used by per-tenant journals which live at
    /// `<base_dir>/spend/<tenant>/<month>.jsonl` rather than the legacy
    /// `<base_dir>/spend/<month>.jsonl` layout.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be created or the
    /// current-month journal file cannot be opened for append.
    pub fn open_in(spend_dir: &Path) -> Result<Self> {
        fs::create_dir_all(spend_dir)
            .with_context(|| format!("failed to create spend dir: {}", spend_dir.display()))?;

        let month = crate::features::token_pricing::spend::current_month();
        let file = Self::open_month_file(spend_dir, &month)?;

        Ok(Self {
            spend_dir: spend_dir.to_path_buf(),
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
    ///
    /// # Errors
    ///
    /// Returns an error if the journal exists but cannot be read or contains
    /// an unparseable line. A missing file is not an error: it means no spend
    /// has been recorded this month. See [`Self::replay_file`].
    pub fn replay_current(&self) -> Result<SpendData> {
        let month = &self.current_month;
        let path = self.month_path(month);
        Self::replay_file(&path, month)
    }

    /// Replays a specific month's journal for tenant data.
    ///
    /// # Errors
    ///
    /// Same contract as [`Self::replay_current`]: missing is fine, damaged is
    /// an error.
    pub fn replay_for_tenant(&self, tenant: &str) -> Result<SpendData> {
        let month = &self.current_month;
        let path = self.month_path(month);
        Self::replay_file_for_tenant(&path, month, tenant)
    }

    /// Replays the current-month journal and returns one [`SpendData`]
    /// per tenant id observed in the file.
    ///
    /// Untagged events (those without a `tenant` field) are bucketed under
    /// the [`crate::storage::DEFAULT_TENANT`] key so per-tenant budget
    /// enforcement covers legacy callers identically.
    ///
    /// # Errors
    ///
    /// Same contract as [`Self::replay_current`].
    pub fn replay_all_tenants(&self) -> Result<HashMap<String, SpendData>> {
        let path = self.month_path(&self.current_month);
        let mut out: HashMap<String, SpendData> = HashMap::new();
        let file = match File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("failed to read spend journal: {}", path.display()))
            }
        };
        let reader = BufReader::new(file);
        for (n, line) in reader.lines().enumerate() {
            let line = line.with_context(|| {
                format!(
                    "failed to read spend journal {} at line {}",
                    path.display(),
                    n + 1
                )
            })?;
            if line.is_empty() {
                continue;
            }
            let event = serde_json::from_str::<SpendEvent>(&line).with_context(|| {
                format!(
                    "malformed spend journal {} at line {}",
                    path.display(),
                    n + 1
                )
            })?;
            let tenant_key = event
                .tenant
                .clone()
                .unwrap_or_else(|| crate::storage::DEFAULT_TENANT.to_string());
            let entry = out.entry(tenant_key).or_default();
            entry.total += event.cost_usd;
            *entry.by_provider.entry(event.provider.clone()).or_default() += event.cost_usd;
            *entry.by_model.entry(event.model.clone()).or_default() += event.cost_usd;
            *entry.by_provider_count.entry(event.provider).or_default() += 1;
        }
        Ok(out)
    }

    fn month_path(&self, month: &str) -> PathBuf {
        self.spend_dir.join(format!("{month}.jsonl"))
    }

    /// Reads one journal file into a [`SpendData`].
    ///
    /// Spend is an *authorizing* input (ADR-0030): the budget check consults
    /// the replayed total to decide whether a request may proceed. Treating a
    /// damaged journal as "no spend" would silently reset the counter to zero
    /// and reopen an exhausted budget, so anything other than a cleanly absent
    /// file is an error and the caller must refuse to serve.
    fn replay_file(path: &Path, _expected_month: &str) -> Result<SpendData> {
        let file = match File::open(path) {
            Ok(f) => f,
            // No journal yet simply means nothing has been spent this month.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(SpendData::default()),
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("failed to read spend journal: {}", path.display()))
            }
        };
        let reader = BufReader::new(file);
        let mut data = SpendData::default();

        for (n, line) in reader.lines().enumerate() {
            let line = line.with_context(|| {
                format!(
                    "failed to read spend journal {} at line {}",
                    path.display(),
                    n + 1
                )
            })?;
            if line.is_empty() {
                continue;
            }
            let event = serde_json::from_str::<SpendEvent>(&line).with_context(|| {
                format!(
                    "malformed spend journal {} at line {}",
                    path.display(),
                    n + 1
                )
            })?;
            // Skip tenant-scoped events for global replay.
            if event.tenant.is_some() {
                continue;
            }
            data.total += event.cost_usd;
            *data.by_provider.entry(event.provider.clone()).or_default() += event.cost_usd;
            *data.by_model.entry(event.model.clone()).or_default() += event.cost_usd;
            *data.by_provider_count.entry(event.provider).or_default() += 1;
        }
        Ok(data)
    }

    /// Reads one journal file, keeping only events for `tenant`.
    ///
    /// Same fail-closed contract as [`Self::replay_file`].
    fn replay_file_for_tenant(
        path: &Path,
        _expected_month: &str,
        tenant: &str,
    ) -> Result<SpendData> {
        let file = match File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(SpendData::default()),
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("failed to read spend journal: {}", path.display()))
            }
        };
        let reader = BufReader::new(file);
        let mut data = SpendData::default();

        for (n, line) in reader.lines().enumerate() {
            let line = line.with_context(|| {
                format!(
                    "failed to read spend journal {} at line {}",
                    path.display(),
                    n + 1
                )
            })?;
            if line.is_empty() {
                continue;
            }
            let event = serde_json::from_str::<SpendEvent>(&line).with_context(|| {
                format!(
                    "malformed spend journal {} at line {}",
                    path.display(),
                    n + 1
                )
            })?;
            if event.tenant.as_deref() != Some(tenant) {
                continue;
            }
            data.total += event.cost_usd;
            *data.by_provider.entry(event.provider.clone()).or_default() += event.cost_usd;
            *data.by_model.entry(event.model.clone()).or_default() += event.cost_usd;
            *data.by_provider_count.entry(event.provider).or_default() += 1;
        }
        Ok(data)
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
                agent: None,
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
                agent: None,
            })
            .unwrap();

        journal.fsync().unwrap();

        let data = journal.replay_current().unwrap();
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
                agent: None,
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
                agent: None,
            })
            .unwrap();
        journal.fsync().unwrap();

        let global = journal.replay_current().unwrap();
        assert!((global.total - 1.0).abs() < 0.001);

        let tenant = journal.replay_for_tenant("tenant-a").unwrap();
        assert!((tenant.total - 2.0).abs() < 0.001);
    }

    /// A corrupted journal must be refused, not silently treated as no spend.
    ///
    /// This is the fail-open that ADR-0030 forbids: skipping the broken line
    /// would under-report spend, and an unreadable file would report `$0`,
    /// reopening a budget the operator had already exhausted.
    #[test]
    fn malformed_line_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let spend_dir = dir.path().join("spend");
        fs::create_dir_all(&spend_dir).unwrap();

        let month = crate::features::token_pricing::spend::current_month();
        let path = spend_dir.join(format!("{month}.jsonl"));
        fs::write(&path, "{\"ts\":\"t\",\"kind\":\"spend\",\"provider\":\"a\",\"model\":\"b\",\"cost_usd\":1.0}\n{broken\n{\"ts\":\"t\",\"kind\":\"spend\",\"provider\":\"c\",\"model\":\"d\",\"cost_usd\":2.0}\n").unwrap();

        let journal = SpendJournal::open(dir.path()).unwrap();
        let err = journal
            .replay_current()
            .expect_err("a damaged journal must not silently under-report spend");
        assert!(
            err.to_string().contains("malformed spend journal"),
            "error should name the problem, got: {err}"
        );
    }

    #[test]
    fn empty_journal_replays_to_default() {
        let dir = tempfile::tempdir().unwrap();
        let journal = SpendJournal::open(dir.path()).unwrap();
        let data = journal.replay_current().unwrap();
        assert_eq!(data.total, 0.0);
    }
}

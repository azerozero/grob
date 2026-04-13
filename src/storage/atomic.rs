//! Atomic file writes via write-to-tmp + fsync + rename.

use anyhow::{Context, Result};
use std::io::Write;
use std::path::Path;

/// Writes `data` to `path` atomically.
///
/// Creates a sibling temporary file, writes + fsyncs, then renames
/// over the target. `rename(2)` is atomic on ext4/xfs/btrfs.
///
/// # Errors
///
/// Returns an error if the parent directory does not exist, the
/// temporary file cannot be created, or the rename fails.
pub(crate) fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .context("atomic write: path has no parent directory")?;

    let mut tmp = tempfile::NamedTempFile::new_in(parent).with_context(|| {
        format!(
            "atomic write: failed to create temp file in {}",
            parent.display()
        )
    })?;

    tmp.write_all(data)
        .context("atomic write: failed to write data")?;
    tmp.as_file()
        .sync_all()
        .context("atomic write: fsync failed")?;

    tmp.persist(path)
        .map_err(|e| e.error)
        .with_context(|| format!("atomic write: rename to {} failed", path.display()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.json");
        let data = br#"{"key":"value"}"#;

        write_atomic(&path, data).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), data);
    }

    #[test]
    fn overwrite_existing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.json");

        write_atomic(&path, b"first").unwrap();
        write_atomic(&path, b"second").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second");
    }

    #[test]
    fn missing_parent_fails() {
        let path = Path::new("/nonexistent/dir/file.json");
        assert!(write_atomic(path, b"data").is_err());
    }
}

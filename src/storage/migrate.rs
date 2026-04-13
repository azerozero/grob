//! Legacy storage detection.
//!
//! ADR-0013 mandates no automatic migration from redb. This module
//! detects old `grob.db` files and logs a warning.

use std::path::Path;

/// Warns if a legacy redb database file exists in the storage directory.
///
/// Does not migrate data — see ADR-0013. The user can export
/// manually with `grob spend --from-redb` if needed (future helper).
pub fn warn_legacy_redb(base_dir: &Path) {
    let db_path = base_dir.join("grob.db");
    if db_path.exists() {
        tracing::warn!(
            path = %db_path.display(),
            "legacy redb database detected — grob now uses file-based storage (ADR-0013). \
             Spend and token data in grob.db will not be read. \
             See docs/decisions/0013-storage-files-no-redb.md for details."
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_warning_when_no_legacy_file() {
        let dir = tempfile::tempdir().unwrap();
        warn_legacy_redb(dir.path());
    }

    #[test]
    fn warning_when_legacy_file_exists() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("grob.db"), b"fake-redb").unwrap();
        warn_legacy_redb(dir.path());
    }
}

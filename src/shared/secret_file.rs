//! Bounded reads of mounted credentials, checking the opened file rather than its path.

use std::{fs::OpenOptions, io::Read, path::Path};

pub(crate) fn read(path: &Path, limit: usize) -> anyhow::Result<zeroize::Zeroizing<Vec<u8>>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Do not follow a swapped symlink or block on a FIFO/device supplied as a secret.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_OPEN_REPARSE_POINT: inspect the link itself rather than its target.
        options.custom_flags(0x0020_0000);
    }
    let file = options
        .open(path)
        .map_err(|_| anyhow::anyhow!("cannot open protected credential file"))?;
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "credential source must be a regular file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        anyhow::ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "credential file must have owner-only permissions"
        );
    }
    anyhow::ensure!(
        metadata.len() <= limit as u64,
        "credential file exceeds its size limit"
    );
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= limit,
        "credential file exceeds its size limit"
    );
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounds_reads_and_rejects_directories() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, b"synthetic").unwrap();
        crate::auth::token_store::set_owner_only_permissions(&path).unwrap();
        assert_eq!(read(&path, 9).unwrap().as_slice(), b"synthetic");
        assert!(read(&path, 2).is_err());
        assert!(read(dir.path(), 99).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn rejects_links_and_public_permissions() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, b"synthetic").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read(&path, 99).is_err());
        crate::auth::token_store::set_owner_only_permissions(&path).unwrap();
        symlink(&path, dir.path().join("link")).unwrap();
        assert!(read(&dir.path().join("link"), 99).is_err());
    }
}

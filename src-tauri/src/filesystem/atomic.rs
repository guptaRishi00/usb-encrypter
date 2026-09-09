//! Crash-safe and unplug-safe file writing.
//!
//! A vault is never built in place. It is written to a temporary file beside
//! the destination, flushed to the device, and only then renamed over the
//! target. If the USB drive is pulled, the process is killed, or the user
//! cancels, the temporary file is removed and any existing vault at the
//! destination is exactly as it was.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::crypto::random::random_array;
use crate::error::{Result, VaultError};

/// A file being built next to its eventual destination.
///
/// Dropping without calling [`TempVaultFile::commit`] deletes the temporary
/// file. That is the cancellation and error path: it runs on `?`, on panic and
/// on an early return, so a half-written vault cannot be left behind.
pub struct TempVaultFile {
    file: Option<File>,
    temp_path: PathBuf,
    final_path: PathBuf,
    committed: bool,
}

impl TempVaultFile {
    pub fn create(final_path: &Path) -> Result<Self> {
        let dir = final_path
            .parent()
            .ok_or_else(|| VaultError::InvalidInput("That destination has no folder.".into()))?;

        // Random suffix so two VaultDrive windows writing to the same folder
        // cannot collide, and so a stale temp file is never silently reused.
        let tag: [u8; 8] = random_array();
        let suffix: String = tag.iter().map(|b| format!("{b:02x}")).collect();
        let stem = final_path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "vault".into());
        let temp_path = dir.join(format!("{stem}.{suffix}.vdtmp"));

        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .read(true)
            .open(&temp_path)
            .map_err(|e| VaultError::from_io(&e, &temp_path))?;

        Ok(Self {
            file: Some(file),
            temp_path,
            final_path: final_path.to_path_buf(),
            committed: false,
        })
    }

    pub fn file(&mut self) -> &mut File {
        self.file.as_mut().expect("file is only taken on commit")
    }

    pub fn path(&self) -> &Path {
        &self.temp_path
    }

    /// Flush to the physical device, then atomically replace the destination.
    ///
    /// `sync_all` before the rename is the part that matters on a removable
    /// drive: without it the rename can land while the data is still in the
    /// operating system's write cache, and pulling the drive at that moment
    /// leaves a vault-shaped file full of zeros.
    pub fn commit(mut self) -> Result<PathBuf> {
        let mut file = self.file.take().expect("commit runs once");
        file.flush().map_err(|e| VaultError::from_io(&e, &self.temp_path))?;
        file.sync_all().map_err(|e| VaultError::from_io(&e, &self.temp_path))?;
        drop(file);

        // On Windows this is MoveFileEx(MOVEFILE_REPLACE_EXISTING); on Unix it
        // is rename(2). Both replace the destination in one step.
        fs::rename(&self.temp_path, &self.final_path)
            .map_err(|e| VaultError::from_io(&e, &self.final_path))?;

        self.committed = true;
        Ok(self.final_path.clone())
    }
}

impl Drop for TempVaultFile {
    fn drop(&mut self) {
        if !self.committed {
            drop(self.file.take());
            // Best effort. If the drive is already gone there is nothing to
            // clean up on it anyway.
            let _ = fs::remove_file(&self.temp_path);
        }
    }
}

/// Flush an already-committed vault after an in-place edit.
pub fn sync_file(file: &File, path: &Path) -> Result<()> {
    file.sync_all().map_err(|e| VaultError::from_io(&e, path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn commit_replaces_the_destination_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("MyVault.vault");
        fs::write(&target, b"old contents").unwrap();

        let mut tmp = TempVaultFile::create(&target).unwrap();
        tmp.file().write_all(b"new contents").unwrap();
        tmp.commit().unwrap();

        assert_eq!(fs::read(&target).unwrap(), b"new contents");
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("vdtmp"))
            .collect();
        assert!(leftovers.is_empty(), "temp file was not cleaned up");
    }

    #[test]
    fn dropping_without_commit_leaves_the_original_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("MyVault.vault");
        fs::write(&target, b"original").unwrap();

        {
            let mut tmp = TempVaultFile::create(&target).unwrap();
            tmp.file().write_all(b"half-written garbage").unwrap();
            // No commit: this is the cancel / error / unplug path.
        }

        assert_eq!(fs::read(&target).unwrap(), b"original");
        let count = fs::read_dir(dir.path()).unwrap().count();
        assert_eq!(count, 1, "only the original vault should remain");
    }

    #[test]
    fn a_failed_write_leaves_no_partial_vault_at_the_destination() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("New.vault");

        let result: Result<()> = (|| {
            let mut tmp = TempVaultFile::create(&target).unwrap();
            tmp.file().write_all(b"some bytes").unwrap();
            Err(VaultError::Cancelled)
        })();

        assert!(result.is_err());
        assert!(!target.exists(), "cancelled creation must not leave a vault");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn two_temp_files_for_the_same_target_do_not_collide() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("Same.vault");
        let a = TempVaultFile::create(&target).unwrap();
        let b = TempVaultFile::create(&target).unwrap();
        assert_ne!(a.path(), b.path());
    }

    #[test]
    fn the_temp_file_is_readable_while_being_written() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("R.vault");
        let mut tmp = TempVaultFile::create(&target).unwrap();
        tmp.file().write_all(b"abc").unwrap();
        use std::io::Seek;
        tmp.file().seek(std::io::SeekFrom::Start(0)).unwrap();
        let mut buf = Vec::new();
        tmp.file().read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"abc");
    }
}

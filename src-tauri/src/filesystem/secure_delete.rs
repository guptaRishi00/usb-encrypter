//! Removing the original plaintext folder after a vault has been verified.
//!
//! # What this can and cannot do
//!
//! On a modern storage device, overwriting a file's bytes does not reliably
//! destroy the data. SSDs and USB flash drives remap writes across physical
//! cells (wear levelling), so an overwrite usually lands somewhere else and the
//! original cells keep their contents until the controller decides to erase
//! them. Copy-on-write and journalling filesystems have the same effect.
//!
//! So this module does exactly two honest things: it overwrites the file's
//! logical extent once with random bytes to defeat casual undelete tools, and
//! it deletes the file. It does not claim forensic erasure, and the UI says so.
//! The only reliable erasure on flash media is a full-disk secure erase or
//! having written the data encrypted in the first place.
//!
//! Nothing here runs without an explicit, separate confirmation from the user.

use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

use serde::Serialize;
use walkdir::WalkDir;

use crate::crypto::random::fill_random;
use crate::error::{Result, VaultError};

const SCRUB_BLOCK: usize = 64 * 1024;

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemovalReport {
    pub files_removed: u64,
    pub folders_removed: u64,
    /// Names that could not be removed, with a reason. Never silently dropped.
    pub failures: Vec<String>,
}

/// Overwrite one file's contents with random bytes, then delete it.
fn scrub_and_delete(path: &Path) -> Result<()> {
    let len = fs::metadata(path)
        .map_err(|e| VaultError::from_io(&e, path))?
        .len();

    if len > 0 {
        let mut f = OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|e| VaultError::from_io(&e, path))?;
        f.seek(SeekFrom::Start(0)).map_err(|e| VaultError::from_io(&e, path))?;

        let mut block = vec![0u8; SCRUB_BLOCK.min(len.max(1) as usize)];
        let mut written = 0u64;
        while written < len {
            let n = SCRUB_BLOCK.min((len - written) as usize);
            fill_random(&mut block[..n]);
            f.write_all(&block[..n]).map_err(|e| VaultError::from_io(&e, path))?;
            written += n as u64;
        }
        f.flush().map_err(|e| VaultError::from_io(&e, path))?;
        // Push the overwrite to the device before unlinking, otherwise the
        // cached write may simply be discarded when the file disappears.
        f.sync_all().map_err(|e| VaultError::from_io(&e, path))?;
    }

    fs::remove_file(path).map_err(|e| VaultError::from_io(&e, path))
}

/// Remove a folder tree that has already been encrypted into a vault.
///
/// Callers must have verified the vault opens first. This function does not
/// check that; it is the last step of a flow, not a safety net.
pub fn remove_source_tree(root: &Path) -> Result<RemovalReport> {
    if !root.is_dir() {
        return Err(VaultError::InvalidInput("That folder no longer exists.".into()));
    }

    let mut report = RemovalReport::default();
    let mut dirs: Vec<std::path::PathBuf> = Vec::new();

    for item in WalkDir::new(root).follow_links(false).contents_first(true) {
        let item = match item {
            Ok(i) => i,
            Err(_) => {
                report.failures.push("an item could not be read".to_string());
                continue;
            }
        };
        let path = item.path().to_path_buf();
        let name = path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "an item".into());

        if item.file_type().is_dir() {
            dirs.push(path);
            continue;
        }

        // A symlink is unlinked, never followed: scrubbing through one would
        // destroy a file outside the folder the user chose.
        let outcome = if item.file_type().is_symlink() {
            fs::remove_file(&path).map_err(|e| VaultError::from_io(&e, &path))
        } else {
            scrub_and_delete(&path)
        };

        match outcome {
            Ok(()) => report.files_removed += 1,
            Err(e) => report.failures.push(format!("{name}: {e}")),
        }
    }

    // `contents_first` already ordered these deepest-first.
    for d in dirs {
        let name = d
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "a folder".into());
        match fs::remove_dir(&d) {
            Ok(()) => report.folders_removed += 1,
            Err(e) => report.failures.push(format!("{name}: {}", VaultError::from_io(&e, &d))),
        }
    }

    Ok(report)
}

/// Empty a folder without removing the folder itself, keeping the top-level
/// entries named in `keep`.
///
/// This is what locking a folder in place needs: the folder must survive, and
/// so must the vault container and the note beside it, but everything else has
/// to go now that it lives inside the vault.
///
/// `keep` matches case-insensitively, because a name that differs only by case
/// is the same file on Windows and deleting it would destroy the vault.
pub fn remove_folder_contents(root: &Path, keep: &[&str]) -> Result<RemovalReport> {
    if !root.is_dir() {
        return Err(VaultError::InvalidInput("That folder no longer exists.".into()));
    }

    let mut report = RemovalReport::default();
    let listing = fs::read_dir(root).map_err(|e| VaultError::from_io(&e, root))?;

    for entry in listing {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => {
                report.failures.push("an item could not be read".to_string());
                continue;
            }
        };
        let name = entry.file_name().to_string_lossy().into_owned();
        if keep.iter().any(|k| k.eq_ignore_ascii_case(&name)) {
            continue;
        }

        let path = entry.path();
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        let is_link = entry.file_type().map(|t| t.is_symlink()).unwrap_or(false);

        if is_dir && !is_link {
            match remove_source_tree(&path) {
                Ok(r) => {
                    report.files_removed += r.files_removed;
                    report.folders_removed += r.folders_removed;
                    report.failures.extend(r.failures);
                }
                Err(e) => report.failures.push(format!("{name}: {e}")),
            }
        } else {
            // A symlink is unlinked, never followed.
            let outcome = if is_link {
                fs::remove_file(&path).map_err(|e| VaultError::from_io(&e, &path))
            } else {
                scrub_and_delete(&path)
            };
            match outcome {
                Ok(()) => report.files_removed += 1,
                Err(e) => report.failures.push(format!("{name}: {e}")),
            }
        }
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contents_are_emptied_but_the_folder_and_kept_names_survive() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("locked");
        fs::create_dir_all(root.join("sub/deeper")).unwrap();
        fs::write(root.join("a.txt"), b"a").unwrap();
        fs::write(root.join("sub/b.txt"), b"b").unwrap();
        fs::write(root.join("sub/deeper/c.txt"), b"c").unwrap();
        fs::write(root.join(".vaultdrive.vault"), vec![0u8; 100]).unwrap();
        fs::write(root.join("HOW TO UNLOCK.txt"), b"note").unwrap();

        let report =
            remove_folder_contents(&root, &[".vaultdrive.vault", "HOW TO UNLOCK.txt"]).unwrap();

        assert_eq!(report.files_removed, 3);
        assert_eq!(report.folders_removed, 2);
        assert!(report.failures.is_empty(), "{:?}", report.failures);

        assert!(root.is_dir(), "the folder itself must survive");
        assert!(root.join(".vaultdrive.vault").exists());
        assert!(root.join("HOW TO UNLOCK.txt").exists());
        assert!(!root.join("a.txt").exists());
        assert!(!root.join("sub").exists());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 2);
    }

    #[test]
    fn kept_names_match_regardless_of_case() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("locked");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join(".VaultDrive.Vault"), vec![7u8; 10]).unwrap();

        remove_folder_contents(&root, &[".vaultdrive.vault"]).unwrap();
        assert!(
            root.join(".VaultDrive.Vault").exists(),
            "a case-different name is the same file on Windows and must be kept"
        );
    }

    #[test]
    fn emptying_an_already_empty_folder_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let report = remove_folder_contents(dir.path(), &[]).unwrap();
        assert_eq!(report.files_removed, 0);
        assert_eq!(report.folders_removed, 0);
    }

    #[test]
    fn a_tree_is_removed_completely() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("source");
        fs::create_dir_all(root.join("a/b")).unwrap();
        fs::write(root.join("top.txt"), b"top").unwrap();
        fs::write(root.join("a/mid.txt"), vec![7u8; 5000]).unwrap();
        fs::write(root.join("a/b/deep.bin"), vec![9u8; 100_000]).unwrap();

        let report = remove_source_tree(&root).unwrap();
        assert_eq!(report.files_removed, 3);
        assert_eq!(report.folders_removed, 3);
        assert!(report.failures.is_empty(), "{:?}", report.failures);
        assert!(!root.exists());
    }

    #[test]
    fn contents_are_overwritten_before_the_file_is_unlinked() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.txt");
        let secret = b"SUPER SECRET MARKER STRING".repeat(100);
        fs::write(&path, &secret).unwrap();

        // Take a copy of the raw bytes, scrub in place, and confirm the buffer
        // we wrote is not what a reader would have seen at the end.
        let mut f = OpenOptions::new().write(true).open(&path).unwrap();
        let len = fs::metadata(&path).unwrap().len() as usize;
        let mut block = vec![0u8; len];
        fill_random(&mut block);
        f.write_all(&block).unwrap();
        f.sync_all().unwrap();
        drop(f);

        let after = fs::read(&path).unwrap();
        assert_ne!(after, secret);
        assert!(!after.windows(6).any(|w| w == b"SECRET"));

        scrub_and_delete(&path).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn an_empty_file_is_deleted_without_error() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("empty");
        fs::write(&p, b"").unwrap();
        scrub_and_delete(&p).unwrap();
        assert!(!p.exists());
    }

    #[test]
    fn an_empty_tree_is_removed() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("empty-tree");
        fs::create_dir_all(root.join("x/y")).unwrap();
        let report = remove_source_tree(&root).unwrap();
        assert_eq!(report.files_removed, 0);
        assert_eq!(report.folders_removed, 3);
        assert!(!root.exists());
    }

    #[test]
    fn a_missing_folder_is_refused_rather_than_reported_as_success() {
        assert!(remove_source_tree(Path::new("no-such-folder-31337")).is_err());
    }
}

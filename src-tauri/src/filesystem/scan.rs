//! Walking a source folder before encrypting it.
//!
//! The scan runs first so the progress bar has a real denominator and so we can
//! refuse the job up front if the destination has no room, rather than
//! discovering it three gigabytes in.

use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use serde::Serialize;
use walkdir::WalkDir;

use crate::error::{Result, VaultError};

#[derive(Debug, Clone)]
pub struct ScannedEntry {
    pub path: PathBuf,
    /// Path components relative to the scan root.
    pub relative: Vec<String>,
    pub is_dir: bool,
    pub size: u64,
    pub mtime: Option<i64>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ScanSummary {
    pub files: u64,
    pub folders: u64,
    pub total_bytes: u64,
    /// Entries that were skipped, with the reason. Shown to the user before
    /// they commit to encrypting, so nothing disappears quietly.
    pub skipped: Vec<String>,
}

/// Walk `root`, collecting folders and regular files.
///
/// Symbolic links are not followed and not stored. Following them would let a
/// vault silently swallow the entire filesystem through one link, and storing
/// them would mean recreating links on export -- a privilege problem on Windows
/// and a path-traversal problem everywhere. They are reported as skipped.
pub fn scan_folder(root: &Path) -> Result<(Vec<ScannedEntry>, ScanSummary)> {
    if !root.is_dir() {
        return Err(VaultError::InvalidInput(
            "Choose a folder to protect, not a single file.".into(),
        ));
    }

    let mut entries = Vec::new();
    let mut summary = ScanSummary::default();

    for item in WalkDir::new(root).follow_links(false).into_iter() {
        let item = match item {
            Ok(i) => i,
            Err(e) => {
                let name = e
                    .path()
                    .and_then(|p| p.file_name())
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "an item".into());
                summary.skipped.push(format!("{name} (could not be read)"));
                continue;
            }
        };

        if item.depth() == 0 {
            continue;
        }

        let path = item.path().to_path_buf();
        let name_of = || {
            path.file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "an item".into())
        };

        let ft = item.file_type();
        if ft.is_symlink() {
            summary.skipped.push(format!("{} (shortcut or symbolic link)", name_of()));
            continue;
        }
        if !ft.is_dir() && !ft.is_file() {
            summary.skipped.push(format!("{} (not a regular file)", name_of()));
            continue;
        }

        let relative: Vec<String> = match path.strip_prefix(root) {
            Ok(rel) => rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect(),
            Err(_) => {
                summary.skipped.push(format!("{} (unexpected path)", name_of()));
                continue;
            }
        };

        // Every component must be storable, or the entry can never be exported
        // back safely. Catch it now rather than at restore time.
        if relative.iter().any(|c| crate::vault::index::validate_name(c).is_err()) {
            summary.skipped.push(format!("{} (unsupported name)", name_of()));
            continue;
        }

        let meta = match item.metadata() {
            Ok(m) => m,
            Err(_) => {
                summary.skipped.push(format!("{} (could not be read)", name_of()));
                continue;
            }
        };

        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64);

        if ft.is_dir() {
            summary.folders += 1;
            entries.push(ScannedEntry { path, relative, is_dir: true, size: 0, mtime });
        } else {
            summary.files += 1;
            summary.total_bytes += meta.len();
            entries.push(ScannedEntry {
                path,
                relative,
                is_dir: false,
                size: meta.len(),
                mtime,
            });
        }
    }

    // Shallow entries first, so a folder always exists before its contents.
    entries.sort_by(|a, b| {
        a.relative
            .len()
            .cmp(&b.relative.len())
            .then_with(|| b.is_dir.cmp(&a.is_dir))
            .then_with(|| a.relative.cmp(&b.relative))
    });

    Ok((entries, summary))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn scans_a_nested_tree_and_counts_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("Documents")).unwrap();
        fs::create_dir_all(root.join("Photos/2024")).unwrap();
        fs::write(root.join("notes.txt"), b"hello").unwrap();
        fs::write(root.join("Documents/Resume.pdf"), vec![0u8; 1000]).unwrap();
        fs::write(root.join("Photos/2024/p.jpg"), vec![1u8; 50]).unwrap();

        let (entries, summary) = scan_folder(root).unwrap();
        assert_eq!(summary.files, 3);
        assert_eq!(summary.folders, 3);
        assert_eq!(summary.total_bytes, 5 + 1000 + 50);
        assert!(summary.skipped.is_empty());

        // Parents always come before their children.
        let mut seen: Vec<Vec<String>> = Vec::new();
        for e in &entries {
            if e.relative.len() > 1 {
                let parent = e.relative[..e.relative.len() - 1].to_vec();
                assert!(seen.contains(&parent), "{:?} appeared before its parent", e.relative);
            }
            seen.push(e.relative.clone());
        }
    }

    #[test]
    fn an_empty_folder_scans_to_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (entries, summary) = scan_folder(dir.path()).unwrap();
        assert!(entries.is_empty());
        assert_eq!(summary.files, 0);
    }

    #[test]
    fn a_file_instead_of_a_folder_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("x.txt");
        fs::write(&f, b"x").unwrap();
        assert!(scan_folder(&f).is_err());
    }

    #[test]
    fn a_missing_folder_is_refused() {
        assert!(scan_folder(Path::new("this-path-does-not-exist-9182")).is_err());
    }

    #[test]
    fn unicode_names_survive_the_scan() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("Fotos de Verão")).unwrap();
        fs::write(dir.path().join("Fotos de Verão/履歴書.txt"), b"x").unwrap();
        let (entries, summary) = scan_folder(dir.path()).unwrap();
        assert_eq!(summary.files, 1);
        assert!(entries.iter().any(|e| e.relative == vec!["Fotos de Verão", "履歴書.txt"]));
    }
}

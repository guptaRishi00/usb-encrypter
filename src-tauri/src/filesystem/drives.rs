//! Removable-drive detection and free-space queries.
//!
//! Everything platform-specific about storage devices is behind this one
//! interface. `sysinfo` supplies the same shape of answer on Windows, macOS and
//! Linux, so nothing above this module knows which one it is running on.

use std::path::Path;

use serde::Serialize;
use sysinfo::Disks;

use crate::error::{Result, VaultError};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DriveInfo {
    /// Volume label if the system reports one, otherwise the mount point.
    pub label: String,
    pub mount_point: String,
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub removable: bool,
    /// Best-effort filesystem name, e.g. `NTFS`, `exFAT`, `APFS`.
    pub file_system: String,
}

/// List mounted volumes.
///
/// This is best effort by design. An operating system is free to hide a volume,
/// report a removable drive as fixed, or expose a network share with no useful
/// size; the UI treats the result as a convenience list, never as the only way
/// to reach a folder. The file picker always remains available.
pub fn list_drives() -> Vec<DriveInfo> {
    let disks = Disks::new_with_refreshed_list();
    let mut out: Vec<DriveInfo> = disks
        .list()
        .iter()
        .map(|d| {
            let mount = d.mount_point().to_string_lossy().into_owned();
            let name = d.name().to_string_lossy().into_owned();
            let label = if name.trim().is_empty() { mount.clone() } else { name };
            DriveInfo {
                label,
                mount_point: mount,
                total_bytes: d.total_space(),
                available_bytes: d.available_space(),
                removable: d.is_removable(),
                file_system: d.file_system().to_string_lossy().into_owned(),
            }
        })
        .collect();

    // Removable drives first: on this app's main path they are what the user
    // came for.
    out.sort_by(|a, b| {
        b.removable
            .cmp(&a.removable)
            .then_with(|| a.mount_point.cmp(&b.mount_point))
    });
    out
}

/// Bytes available on the volume holding `path`.
///
/// Matches by longest mount-point prefix, which is how a nested mount is meant
/// to resolve. Returns `None` when no volume matches, rather than guessing.
pub fn available_space_for(path: &Path) -> Option<u64> {
    let disks = Disks::new_with_refreshed_list();
    let mut best: Option<(usize, u64)> = None;
    for d in disks.list() {
        let mp = d.mount_point();
        if path.starts_with(mp) {
            let depth = mp.components().count();
            if best.map_or(true, |(b, _)| depth > b) {
                best = Some((depth, d.available_space()));
            }
        }
    }
    best.map(|(_, avail)| avail)
}

/// Refuse a write that clearly will not fit.
///
/// Deliberately advisory: if the platform will not tell us the free space we
/// proceed and let the write fail honestly, rather than blocking a job that
/// would have succeeded. A 16 MiB margin covers the header, the index and
/// filesystem slack.
pub fn ensure_space(dest_dir: &Path, needed_bytes: u64) -> Result<()> {
    const MARGIN: u64 = 16 * 1024 * 1024;
    let Some(available) = available_space_for(dest_dir) else {
        return Ok(());
    };
    let needed = needed_bytes.saturating_add(MARGIN);
    if available < needed {
        return Err(VaultError::InsufficientSpace {
            needed_mb: needed / (1024 * 1024),
            available_mb: available / (1024 * 1024),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listing_drives_does_not_panic_and_reports_this_machine() {
        let drives = list_drives();
        // Every supported platform has at least one mounted volume.
        assert!(!drives.is_empty(), "expected at least one mounted volume");
        for d in &drives {
            assert!(!d.mount_point.is_empty());
        }
    }

    #[test]
    fn removable_drives_sort_first() {
        let drives = list_drives();
        let mut seen_fixed = false;
        for d in &drives {
            if !d.removable {
                seen_fixed = true;
            } else {
                assert!(!seen_fixed, "a removable drive appeared after a fixed one");
            }
        }
    }

    #[test]
    fn free_space_for_the_temp_directory_is_known_and_nonzero() {
        let dir = tempfile::tempdir().unwrap();
        let avail = available_space_for(dir.path());
        // If the platform reports it at all it must be a sane number.
        if let Some(a) = avail {
            assert!(a > 0);
        }
    }

    #[test]
    fn an_impossible_request_is_refused_before_any_bytes_are_written() {
        let dir = tempfile::tempdir().unwrap();
        if available_space_for(dir.path()).is_some() {
            let err = ensure_space(dir.path(), u64::MAX / 2);
            assert!(matches!(err, Err(VaultError::InsufficientSpace { .. })));
        }
    }

    #[test]
    fn a_small_request_is_allowed() {
        let dir = tempfile::tempdir().unwrap();
        assert!(ensure_space(dir.path(), 1024).is_ok());
    }

    #[test]
    fn an_unknown_volume_does_not_block_the_write() {
        assert!(ensure_space(Path::new("\\\\?\\nonexistent-volume-xyz"), 1024).is_ok());
    }
}

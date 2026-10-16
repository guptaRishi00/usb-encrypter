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

/// Free bytes and filesystem name of the volume holding `path`.
///
/// Matches by longest mount-point prefix, which is how a nested mount is meant
/// to resolve. Returns `None` when no volume matches, rather than guessing.
fn volume_for(path: &Path) -> Option<(u64, String)> {
    let disks = Disks::new_with_refreshed_list();
    let mut best: Option<(usize, u64, String)> = None;
    for d in disks.list() {
        let mp = d.mount_point();
        if path.starts_with(mp) {
            let depth = mp.components().count();
            if best.as_ref().map_or(true, |(b, _, _)| depth > *b) {
                let fs = d.file_system().to_string_lossy().into_owned();
                best = Some((depth, d.available_space(), fs));
            }
        }
    }
    best.map(|(_, avail, fs)| (avail, fs))
}

/// Bytes available on the volume holding `path`, if the platform reports it.
pub fn available_space_for(path: &Path) -> Option<u64> {
    volume_for(path).map(|(avail, _)| avail)
}

/// Filesystem name of the volume holding `path`, if the platform reports it.
pub fn file_system_for(path: &Path) -> Option<String> {
    volume_for(path).map(|(_, fs)| fs)
}

/// The largest file FAT32 can hold: one byte short of 4 GiB.
const FAT_MAX_FILE_BYTES: u64 = (4 << 30) - 1;

/// Headroom for a vault container's tags and index on top of its plaintext
/// total. Harmless for a plain file, which is at most a megabyte smaller than
/// the limit when this wrongly refuses it.
const CONTAINER_SLACK: u64 = 1024 * 1024;

/// Whether a filesystem name is FAT12/16/32, which share the 4 GiB file cap.
///
/// Windows reports `FAT32`/`FAT`, Linux `vfat`, macOS `msdos`. exFAT has no
/// such limit and must not match, hence exact names rather than a substring.
fn is_fat_family(file_system: &str) -> bool {
    let name = file_system.trim().to_ascii_lowercase();
    name.starts_with("fat") || name == "vfat" || name == "msdos"
}

fn fits_on(file_system: &str, file_bytes: u64) -> bool {
    !is_fat_family(file_system) || file_bytes.saturating_add(CONTAINER_SLACK) <= FAT_MAX_FILE_BYTES
}

/// Refuse a single file the destination filesystem cannot hold.
///
/// FAT32 is still the factory format of most USB sticks and caps every file at
/// 4 GiB. A vault is one file, so a large folder would otherwise fail part-way
/// with a misleading "disk full" from the OS. Advisory like [`ensure_space`]:
/// an unknown volume is allowed through.
pub fn ensure_file_fits(dest_dir: &Path, file_bytes: u64) -> Result<()> {
    let Some(file_system) = file_system_for(dest_dir) else {
        return Ok(());
    };
    if fits_on(&file_system, file_bytes) {
        return Ok(());
    }
    Err(VaultError::FileTooLargeForVolume {
        file_system,
        size_mb: file_bytes / (1024 * 1024),
    })
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

    #[test]
    fn fat_family_names_are_recognised_whatever_the_platform_calls_them() {
        for n in ["FAT32", "FAT", "fat16", "vfat", "msdos", " FAT32 "] {
            assert!(is_fat_family(n), "{n:?} should count as FAT");
        }
        for n in ["exFAT", "exfat", "NTFS", "APFS", "ext4", ""] {
            assert!(!is_fat_family(n), "{n:?} must not count as FAT");
        }
    }

    #[test]
    fn only_fat_volumes_cap_a_file_at_four_gib() {
        assert!(fits_on("FAT32", 1 << 30));
        assert!(!fits_on("FAT32", 4 << 30));
        assert!(!fits_on("vfat", (4 << 30) - 1));
        assert!(fits_on("exFAT", 10 << 30));
        assert!(fits_on("NTFS", u64::MAX));
    }

    #[test]
    fn a_large_file_is_refused_only_on_fat_volumes() {
        let dir = tempfile::tempdir().unwrap();
        let result = ensure_file_fits(dir.path(), 10 << 30);
        match file_system_for(dir.path()) {
            Some(fs) if is_fat_family(&fs) => {
                assert!(matches!(result, Err(VaultError::FileTooLargeForVolume { .. })));
            }
            _ => assert!(result.is_ok()),
        }
    }

    #[test]
    fn an_unknown_volume_does_not_block_a_large_file() {
        assert!(ensure_file_fits(Path::new("\\\\?\\nonexistent-volume-xyz"), 10 << 30).is_ok());
    }
}

//! The "hidden" flag on VaultDrive's own files in a locked folder.
//!
//! A locked folder should show one thing to double-click, not a vault, four
//! launchers and a note. Everything except the program itself is marked
//! hidden, which Explorer and Finder respect by default. macOS also honours the
//! Windows flag on FAT and exFAT drives, so a stick hidden on Windows stays
//! tidy on a Mac.
//!
//! On Windows the files are marked hidden *and* system, the pair `desktop.ini`
//! uses. Plenty of people switch on "Show hidden items"; far fewer switch off
//! "Hide protected operating system files", so this keeps the folder down to
//! the one program for nearly everyone.
//!
//! Hiding is cosmetic, never a security measure: the contents are protected by
//! encryption, and anyone who changes those Explorer settings simply sees the
//! files again. Every call here is best effort for the same reason.

use std::io;
use std::path::Path;

/// Set or clear the hidden flag (hidden + system on Windows). Returns whether
/// it was applied.
pub fn set_hidden(path: &Path, hidden: bool) -> bool {
    imp::set_hidden(path, hidden)
}

/// Whether the platform reports `path` as hidden. `None` where the platform
/// has no such flag, or the file cannot be read.
pub fn is_hidden(path: &Path) -> Option<bool> {
    imp::is_hidden(path)
}

/// Write a file that may already exist with the hidden flag set.
///
/// Windows refuses to overwrite a hidden or system file through a plain create
/// (`ERROR_ACCESS_DENIED`), so the flags are cleared first. The caller hides it
/// again once everything is written.
pub fn write_replacing(path: &Path, contents: impl AsRef<[u8]>) -> io::Result<()> {
    if path.exists() {
        set_hidden(path, false);
    }
    std::fs::write(path, contents)
}

#[cfg(windows)]
mod imp {
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetFileAttributesW(name: *const u16) -> u32;
        fn SetFileAttributesW(name: *const u16, attributes: u32) -> i32;
    }
    const INVALID_FILE_ATTRIBUTES: u32 = u32::MAX;
    const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
    const FILE_ATTRIBUTE_SYSTEM: u32 = 0x4;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    const OUT_OF_SIGHT: u32 = FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM;

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
    }

    fn attributes(name: &[u16]) -> Option<u32> {
        // SAFETY: `name` is a NUL-terminated UTF-16 path owned by the caller.
        let a = unsafe { GetFileAttributesW(name.as_ptr()) };
        (a != INVALID_FILE_ATTRIBUTES).then_some(a)
    }

    pub fn set_hidden(path: &Path, hidden: bool) -> bool {
        let name = wide(path);
        let Some(current) = attributes(&name) else {
            return false;
        };
        // NORMAL is only valid on its own, so it never survives a combination.
        let next = if hidden {
            (current & !FILE_ATTRIBUTE_NORMAL) | OUT_OF_SIGHT
        } else {
            match current & !OUT_OF_SIGHT {
                0 => FILE_ATTRIBUTE_NORMAL,
                other => other,
            }
        };
        // SAFETY: as above; the attribute value is built from the file's own.
        unsafe { SetFileAttributesW(name.as_ptr(), next) != 0 }
    }

    pub fn is_hidden(path: &Path) -> Option<bool> {
        attributes(&wide(path)).map(|a| a & FILE_ATTRIBUTE_HIDDEN != 0)
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use std::path::Path;

    /// `UF_HIDDEN` from `<sys/stat.h>`.
    const UF_HIDDEN: u32 = 0x8000;

    pub fn set_hidden(path: &Path, hidden: bool) -> bool {
        std::process::Command::new("/usr/bin/chflags")
            .arg(if hidden { "hidden" } else { "nohidden" })
            .arg(path)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    pub fn is_hidden(path: &Path) -> Option<bool> {
        use std::os::macos::fs::MetadataExt;
        std::fs::symlink_metadata(path).ok().map(|m| m.st_flags() & UF_HIDDEN != 0)
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
mod imp {
    use std::path::Path;

    // Linux file managers hide dot-files and nothing else; there is no flag.
    pub fn set_hidden(_path: &Path, _hidden: bool) -> bool {
        false
    }

    pub fn is_hidden(_path: &Path) -> Option<bool> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hidden_file_can_be_overwritten_and_unhidden() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("note.txt");
        std::fs::write(&p, "one").unwrap();

        if set_hidden(&p, true) {
            assert_eq!(is_hidden(&p), Some(true));
        }
        // The case Windows gets wrong without help: replacing a hidden file.
        write_replacing(&p, "two").unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "two");

        set_hidden(&p, false);
        assert_ne!(is_hidden(&p), Some(true));
    }

    #[test]
    fn a_missing_file_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!set_hidden(&dir.path().join("absent"), true));
        assert_eq!(is_hidden(&dir.path().join("absent")).unwrap_or(false), false);
    }
}

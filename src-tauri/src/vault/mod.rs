//! The vault format and everything that reads or writes it.

pub mod container;
pub mod format;
pub mod index;
pub mod progress;
pub mod session;

pub use container::{now_secs, OpenVault, VaultBuilder, PREVIEW_LIMIT};
pub use format::{Header, FORMAT_VERSION};
pub use index::{NodeKind, VaultIndex, ROOT_ID};
pub use progress::{CancelFlag, NoProgress, ProgressSink, ProgressSnapshot};
pub use session::VaultSession;

use std::path::Path;

use crate::crypto::KdfParams;
use crate::error::{Result, VaultError};
use crate::filesystem::scan::ScanSummary;

// ---------------------------------------------------------------------------
// Locking a folder in place
// ---------------------------------------------------------------------------

/// The container written inside a folder that has been locked in place.
///
/// A fixed name, so "is this folder locked?" is one `exists()` call rather than
/// a guess based on whatever `.vault` files happen to be lying around.
pub const IN_PLACE_VAULT_NAME: &str = ".vaultdrive.vault";

/// A plain-text note left beside it, so someone who finds the folder without
/// VaultDrive installed understands what happened to their files.
pub const IN_PLACE_README_NAME: &str = "HOW TO UNLOCK.txt";

/// The launchers that make a locked folder self-contained on another machine.
///
/// `Unlock.cmd` and `Lock.cmd` run the copied executable in console mode, which
/// asks for the password and works on the folder they sit in. No installation,
/// no window, and no WebView2 are needed on the other computer: console mode
/// never starts the interface.
pub const LAUNCHER_EXE_NAME: &str = "VaultDrive.exe";
pub const UNLOCK_CMD_NAME: &str = "Unlock.cmd";
pub const LOCK_CMD_NAME: &str = "Lock.cmd";

/// Every file VaultDrive itself puts in a locked folder. None of these is ever
/// encrypted into the vault, and none is deleted when the plaintext is.
pub const IN_PLACE_ARTIFACTS: [&str; 5] = [
    IN_PLACE_VAULT_NAME,
    IN_PLACE_README_NAME,
    LAUNCHER_EXE_NAME,
    UNLOCK_CMD_NAME,
    LOCK_CMD_NAME,
];

/// Build one of the launchers.
///
/// `%~dp0` is the folder the .cmd lives in, trailing backslash included, so
/// `"%~dp0."` names that folder without a trailing slash inside the quotes.
/// `cd /d` first, so a drive-letter change on a USB stick is harmless. Lines
/// are joined with CRLF because cmd.exe misreads a bare LF in some constructs.
fn launcher_text(flag: &str) -> String {
    let lines = [
        "@echo off".to_string(),
        "setlocal".to_string(),
        "cd /d \"%~dp0\"".to_string(),
        "if not exist \"%~dp0VaultDrive.exe\" (".to_string(),
        "  echo VaultDrive.exe is missing from this folder.".to_string(),
        "  echo Open this folder with the VaultDrive application instead.".to_string(),
        "  pause".to_string(),
        "  exit /b 1".to_string(),
        ")".to_string(),
        format!("\"%~dp0VaultDrive.exe\" {flag} \"%~dp0.\""),
        "echo.".to_string(),
        "pause".to_string(),
    ];
    let mut out = lines.join("\r\n");
    out.push_str("\r\n");
    out
}

const IN_PLACE_README: &str = "\
This folder is locked by VaultDrive.
====================================

Everything that was in here is now inside .vaultdrive.vault, encrypted with
XChaCha20-Poly1305 under a key derived from a password with Argon2id.

To get the files back:

  * If Unlock.cmd is in this folder, double-click it and type the password.
    It works on any Windows computer, with nothing installed.

  * Otherwise open VaultDrive, choose \"Open Vault\", switch to \"Locked
    folder\", pick this folder, and enter the password.

Either way the files are restored exactly where they were and the vault file
disappears. Lock.cmd locks the folder again afterwards.

There is no master password and no backdoor. If the password is forgotten,
nothing in this folder can be recovered, by anyone.

Do not edit, rename or repair .vaultdrive.vault with any other tool. Any
change to it is detected as tampering and VaultDrive will refuse to open it
rather than hand back damaged files.
";

fn is_in_place_artifact(relative: &[String]) -> bool {
    relative.len() == 1
        && IN_PLACE_ARTIFACTS.iter().any(|a| relative[0].eq_ignore_ascii_case(a))
}

/// Copy this executable and the two launchers into `folder`.
///
/// Copying the running binary is what makes the folder open on a machine that
/// has never seen VaultDrive. If the copy already exists (a re-lock), it is
/// refreshed so the folder always carries the version that locked it.
fn write_launchers(folder: &Path) -> Result<()> {
    let exe_dst = folder.join(LAUNCHER_EXE_NAME);
    let exe_src = std::env::current_exe()
        .map_err(|_| VaultError::Io("Could not locate the VaultDrive executable.".into()))?;
    let same = std::fs::canonicalize(&exe_src).ok()
        == std::fs::canonicalize(&exe_dst).ok();
    if !same {
        std::fs::copy(&exe_src, &exe_dst).map_err(|e| VaultError::from_io(&e, &exe_dst))?;
    }
    for (name, flag) in [(UNLOCK_CMD_NAME, "--unlock-folder"), (LOCK_CMD_NAME, "--lock-folder")] {
        let p = folder.join(name);
        std::fs::write(&p, launcher_text(flag)).map_err(|e| VaultError::from_io(&e, &p))?;
    }
    Ok(())
}

/// Whether a folder currently holds a VaultDrive in-place vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FolderLockState {
    /// The folder holds `.vaultdrive.vault`; its contents are encrypted.
    Locked,
    /// An ordinary folder with something in it.
    Unlocked,
    /// Nothing to lock.
    Empty,
    /// The path is not a folder, or cannot be read.
    Unavailable,
}

pub fn folder_lock_state(folder: &Path) -> FolderLockState {
    if !folder.is_dir() {
        return FolderLockState::Unavailable;
    }
    if folder.join(IN_PLACE_VAULT_NAME).is_file() {
        return FolderLockState::Locked;
    }
    match std::fs::read_dir(folder) {
        Ok(mut entries) => {
            if entries.next().is_some() {
                FolderLockState::Unlocked
            } else {
                FolderLockState::Empty
            }
        }
        Err(_) => FolderLockState::Unavailable,
    }
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LockReport {
    pub folder: String,
    pub files: u64,
    pub folders: u64,
    pub total_bytes: u64,
    pub skipped: Vec<String>,
    pub verified: bool,
    /// Plaintext entries removed from the folder once the vault was verified.
    pub removed_files: u64,
    pub removed_folders: u64,
    pub removal_failures: Vec<String>,
    /// Whether `VaultDrive.exe`, `Unlock.cmd` and `Lock.cmd` were placed in
    /// the folder so it opens on a machine without VaultDrive.
    pub launchers: bool,
}

/// Encrypt everything in `folder` into a container inside that same folder,
/// then delete the plaintext.
///
/// The folder keeps its name and its place. What changes is that its contents
/// become one opaque file. This is real encryption, not a permission or
/// attribute trick: an administrator, another operating system, or the drive
/// plugged into a different machine all see the same unreadable bytes.
///
/// Order is deliberate and is the safety argument:
///
/// 1. Scan, and refuse if the folder is already locked.
/// 2. Build the vault to a temporary file, renamed into place atomically.
/// 3. **Reopen it with the same password and confirm the file count.**
/// 4. Only then delete the plaintext.
///
/// A failure at any point before step 4 leaves every original file untouched.
pub fn lock_folder_in_place(
    folder: &Path,
    password: &[u8],
    kdf_params: KdfParams,
    launchers: bool,
    progress: &dyn ProgressSink,
) -> Result<LockReport> {
    if password.is_empty() {
        return Err(VaultError::InvalidInput(
            "Enter a password. A folder locked with no password protects nothing.".into(),
        ));
    }
    match folder_lock_state(folder) {
        FolderLockState::Locked => {
            return Err(VaultError::AlreadyExists {
                name: folder
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "that folder".into()),
            })
        }
        FolderLockState::Empty => {
            return Err(VaultError::InvalidInput(
                "That folder is empty. There is nothing to lock.".into(),
            ))
        }
        FolderLockState::Unavailable => {
            return Err(VaultError::InvalidInput("That folder cannot be read.".into()))
        }
        FolderLockState::Unlocked => {}
    }

    let vault_path = folder.join(IN_PLACE_VAULT_NAME);
    let display_name = folder
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "Vault".into());

    let (all_entries, summary) = crate::filesystem::scan_folder(folder)?;
    // Never store our own artefacts from a previous run inside the new vault.
    let entries: Vec<_> =
        all_entries.into_iter().filter(|e| !is_in_place_artifact(&e.relative)).collect();

    let files = entries.iter().filter(|e| !e.is_dir).count() as u64;
    let folders = entries.iter().filter(|e| e.is_dir).count() as u64;
    let total_bytes: u64 = entries.iter().filter(|e| !e.is_dir).map(|e| e.size).sum();
    if files == 0 && folders == 0 {
        return Err(VaultError::InvalidInput(
            "That folder has nothing in it that can be locked.".into(),
        ));
    }

    // The vault is written beside the plaintext it is encrypting, so the volume
    // briefly holds both copies. Check for that up front rather than running
    // out of room with the originals half-deleted.
    crate::filesystem::ensure_space(folder, total_bytes)?;

    tracing::info!(files, folders, total_bytes, "locking folder in place");

    let mut builder = VaultBuilder::begin(&vault_path, password, &display_name, kdf_params)?;
    let mut dir_ids: std::collections::HashMap<Vec<String>, u64> = std::collections::HashMap::new();
    dir_ids.insert(Vec::new(), ROOT_ID);

    let mut files_done = 0u64;
    let mut bytes_done = 0u64;

    for e in entries {
        if progress.is_cancelled() {
            return Err(VaultError::Cancelled);
        }
        let parent_key = e.relative[..e.relative.len() - 1].to_vec();
        let parent = *dir_ids.get(&parent_key).ok_or(VaultError::Integrity)?;
        let name = e.relative.last().cloned().unwrap_or_default();

        if e.is_dir {
            let id = builder.add_dir(parent, &name, e.mtime)?;
            dir_ids.insert(e.relative.clone(), id);
        } else {
            let mut f = std::fs::File::open(&e.path).map_err(|err| match err.kind() {
                std::io::ErrorKind::NotFound => VaultError::SourceChanged { name: name.clone() },
                _ => VaultError::from_io(&err, &e.path),
            })?;
            builder.add_file(parent, &name, &mut f, e.size, e.mtime, progress, &mut |n| {
                bytes_done += n;
            })?;
            files_done += 1;
            progress.report(
                ProgressSnapshot { files_done, total_files: files, bytes_done, total_bytes },
                &name,
            );
        }
    }

    let written = builder.finish()?;

    // Prove the vault opens before a single original is deleted.
    let verified = match OpenVault::unlock(&written, password) {
        Ok(v) => {
            let (stored, _, _) = v.index().stats();
            drop(v);
            stored == files
        }
        Err(e) => {
            tracing::error!(kind = e.kind(), "verification of a freshly locked folder failed");
            let _ = std::fs::remove_file(&written);
            return Err(e);
        }
    };
    if !verified {
        let _ = std::fs::remove_file(&written);
        return Err(VaultError::Integrity);
    }

    let readme_path = folder.join(IN_PLACE_README_NAME);
    let _ = std::fs::write(&readme_path, IN_PLACE_README);
    if launchers {
        write_launchers(folder)?;
    }

    let removal = crate::filesystem::secure_delete::remove_folder_contents(
        folder,
        &IN_PLACE_ARTIFACTS,
    )?;

    tracing::info!(
        removed_files = removal.files_removed,
        removed_folders = removal.folders_removed,
        "folder locked in place"
    );

    Ok(LockReport {
        folder: folder.to_string_lossy().into_owned(),
        files,
        folders,
        total_bytes,
        skipped: summary.skipped,
        verified,
        removed_files: removal.files_removed,
        removed_folders: removal.folders_removed,
        removal_failures: removal.failures,
        launchers,
    })
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockReport {
    pub folder: String,
    pub files: u64,
    pub folders: u64,
    pub total_bytes: u64,
}

/// Restore a folder locked by [`lock_folder_in_place`].
///
/// The contents come back where they were and the container is removed, so the
/// folder is an ordinary folder again. The vault file is only deleted after
/// every file has been written out, so an interrupted unlock leaves the vault
/// intact and can simply be run again.
pub fn unlock_folder_in_place(
    folder: &Path,
    password: &[u8],
    progress: &dyn ProgressSink,
) -> Result<UnlockReport> {
    let vault_path = folder.join(IN_PLACE_VAULT_NAME);
    if !vault_path.is_file() {
        return Err(VaultError::InvalidInput(
            "That folder is not locked by VaultDrive.".into(),
        ));
    }

    let mut vault = OpenVault::unlock(&vault_path, password)?;
    let (files, folders, total_bytes) = vault.index().stats();

    // Restoring puts the plaintext beside the vault that still holds it.
    crate::filesystem::ensure_space(folder, total_bytes)?;

    // Export each top-level entry directly into the folder, rather than into a
    // subfolder named after the vault: the point is to restore in place.
    let top: Vec<u64> = vault.index().children(ROOT_ID).iter().map(|n| n.id).collect();
    for id in top {
        if progress.is_cancelled() {
            return Err(VaultError::Cancelled);
        }
        vault.export(id, folder, progress)?;
    }
    drop(vault);

    // Everything is back on disk; the container has no further purpose.
    std::fs::remove_file(&vault_path).map_err(|e| VaultError::from_io(&e, &vault_path))?;
    let _ = std::fs::remove_file(folder.join(IN_PLACE_README_NAME));

    tracing::info!(files, folders, "folder unlocked in place");

    Ok(UnlockReport {
        folder: folder.to_string_lossy().into_owned(),
        files,
        folders,
        total_bytes,
    })
}

/// Outcome of building a vault from a source folder.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateReport {
    pub vault_path: String,
    pub files: u64,
    pub folders: u64,
    pub total_bytes: u64,
    /// Entries the scan refused to store, each with a reason.
    pub skipped: Vec<String>,
    /// Set once the finished vault has been reopened with the same password.
    pub verified: bool,
}

/// Encrypt a folder into a new `.vault` container.
///
/// The whole job runs through [`VaultBuilder`], which writes to a temporary
/// file beside the destination. Cancellation, an unplugged drive, a full disk
/// or any other failure drops the builder, which deletes that temporary file
/// and leaves the source folder and any existing vault untouched.
pub fn create_vault_from_folder(
    source: &Path,
    dest_vault: &Path,
    password: &[u8],
    vault_name: &str,
    kdf_params: KdfParams,
    progress: &dyn ProgressSink,
) -> Result<CreateReport> {
    if password.is_empty() {
        return Err(VaultError::InvalidInput(
            "Enter a password. A vault with no password protects nothing.".into(),
        ));
    }
    if dest_vault.exists() {
        return Err(VaultError::AlreadyExists {
            name: dest_vault
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "that vault".into()),
        });
    }

    let (entries, summary) = crate::filesystem::scan_folder(source)?;
    let dest_dir = dest_vault
        .parent()
        .ok_or_else(|| VaultError::InvalidInput("That destination has no folder.".into()))?;
    // Ciphertext is very slightly larger than plaintext (16 bytes per megabyte
    // plus the index), so the plaintext total plus the module's own margin is a
    // safe estimate.
    crate::filesystem::ensure_space(dest_dir, summary.total_bytes)?;

    let ScanSummary { files, folders, total_bytes, skipped } = summary;
    tracing::info!(files, folders, total_bytes, "creating vault");

    let mut builder = VaultBuilder::begin(dest_vault, password, vault_name, kdf_params)?;
    let mut dir_ids: std::collections::HashMap<Vec<String>, u64> = std::collections::HashMap::new();
    dir_ids.insert(Vec::new(), ROOT_ID);

    let mut files_done = 0u64;
    let mut bytes_done = 0u64;

    for e in entries {
        if progress.is_cancelled() {
            return Err(VaultError::Cancelled);
        }
        let parent_key = e.relative[..e.relative.len() - 1].to_vec();
        let parent = *dir_ids.get(&parent_key).ok_or(VaultError::Integrity)?;
        let name = e.relative.last().cloned().unwrap_or_default();

        if e.is_dir {
            let id = builder.add_dir(parent, &name, e.mtime)?;
            dir_ids.insert(e.relative.clone(), id);
        } else {
            let mut f = std::fs::File::open(&e.path).map_err(|err| {
                // A file that vanished between the scan and now is a changed
                // source, not a corrupt vault.
                match err.kind() {
                    std::io::ErrorKind::NotFound => {
                        VaultError::SourceChanged { name: name.clone() }
                    }
                    _ => VaultError::from_io(&err, &e.path),
                }
            })?;
            builder.add_file(parent, &name, &mut f, e.size, e.mtime, progress, &mut |n| {
                bytes_done += n;
            })?;
            files_done += 1;
            progress.report(
                ProgressSnapshot { files_done, total_files: files, bytes_done, total_bytes },
                &name,
            );
        }
    }

    let written = builder.finish()?;

    // Step 10 of the create flow: prove the vault we just wrote opens with the
    // password the user typed, before offering to delete anything.
    let verified = match OpenVault::unlock(&written, password) {
        Ok(v) => {
            let (f, _, _) = v.index().stats();
            drop(v);
            f == files
        }
        Err(e) => {
            tracing::error!(kind = e.kind(), "verification of a freshly written vault failed");
            return Err(e);
        }
    };

    Ok(CreateReport {
        vault_path: written.to_string_lossy().into_owned(),
        files,
        folders,
        total_bytes,
        skipped,
        verified,
    })
}

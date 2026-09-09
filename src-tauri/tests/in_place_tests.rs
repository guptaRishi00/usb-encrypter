//! Locking a folder in place: the folder keeps its name and its location, and
//! its contents become one encrypted container inside it.

mod common;

use std::fs;
use std::path::Path;

use common::Fixture;
use vaultdrive_lib::error::VaultError;
use vaultdrive_lib::vault::{
    folder_lock_state, lock_folder_in_place, unlock_folder_in_place, FolderLockState, NoProgress,
    IN_PLACE_README_NAME, IN_PLACE_VAULT_NAME,
};

fn sample(fx: &Fixture) -> std::path::PathBuf {
    fx.source(
        "Secret",
        &[
            ("notes.txt", b"top level note"),
            ("Documents/Resume.txt", b"CURRICULUM VITAE"),
            ("Documents/empty.txt", b""),
            ("Photos/2024/holiday.bin", &[0x5Au8; 5000]),
        ],
    )
}

fn lock(folder: &Path, password: &str) -> vaultdrive_lib::error::Result<()> {
    lock_folder_in_place(folder, password.as_bytes(), common::fast_kdf(), false, &NoProgress)
        .map(|_| ())
}

fn lock_with_launchers(folder: &Path, password: &str) -> vaultdrive_lib::error::Result<()> {
    lock_folder_in_place(folder, password.as_bytes(), common::fast_kdf(), true, &NoProgress)
        .map(|_| ())
}

#[test]
fn launchers_make_the_folder_self_contained() {
    use vaultdrive_lib::vault::{LAUNCHER_EXE_NAME, LOCK_CMD_NAME, UNLOCK_CMD_NAME};

    let fx = Fixture::new();
    let folder = sample(&fx);
    let before = tree(&folder);
    lock_with_launchers(&folder, "gravel-tunnel-9").unwrap();

    // The executable that did the locking travels with the folder.
    let exe = folder.join(LAUNCHER_EXE_NAME);
    assert!(exe.is_file(), "VaultDrive.exe should be copied in");
    assert_eq!(
        fs::read(&exe).unwrap(),
        fs::read(std::env::current_exe().unwrap()).unwrap(),
        "the copy must be this exact binary"
    );

    for (name, flag) in [(UNLOCK_CMD_NAME, "--unlock-folder"), (LOCK_CMD_NAME, "--lock-folder")] {
        let text = fs::read_to_string(folder.join(name)).unwrap();
        assert!(text.contains(flag), "{name} must invoke {flag}");
        assert!(text.contains("%~dp0VaultDrive.exe"), "{name} must run the copied exe");
        assert!(text.contains("\r\n"), "{name} must use CRLF for cmd.exe");
        assert!(!text.contains("gravel-tunnel-9"), "{name} must not contain the password");
    }

    // The Mac launchers are written too, so a Mac user is told exactly what is
    // missing rather than hitting a shell error.
    use vaultdrive_lib::vault::{LAUNCHER_MAC_NAME, LOCK_COMMAND_NAME, UNLOCK_COMMAND_NAME};
    for (name, flag) in
        [(UNLOCK_COMMAND_NAME, "--unlock-folder"), (LOCK_COMMAND_NAME, "--lock-folder")]
    {
        let text = fs::read_to_string(folder.join(name)).unwrap();
        assert!(text.starts_with("#!/bin/bash\n"), "{name} must be a bash script");
        assert!(!text.contains('\r'), "{name} must use LF only; bash chokes on CR");
        assert!(text.contains(flag), "{name} must invoke {flag}");
        assert!(text.contains(LAUNCHER_MAC_NAME), "{name} must run the Mac binary");
        assert!(text.contains("chmod +x"), "{name} must restore the executable bit");
        assert!(text.contains("not in this folder"), "{name} must explain a missing Mac binary");
        assert!(!text.contains("gravel-tunnel-9"), "{name} must not contain the password");
    }
    // This build is Windows, so it contributes only the Windows binary: the
    // Mac one is deliberately absent, and the .command says so.
    assert!(!folder.join(LAUNCHER_MAC_NAME).exists());

    // Exactly seven things remain, and none of them is plaintext from the user.
    let left: Vec<String> = fs::read_dir(&folder)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(left.len(), 7, "{left:?}");

    // Unlocking restores the contents and KEEPS the launchers, so the folder
    // can be locked again on the other machine.
    unlock_folder_in_place(&folder, b"gravel-tunnel-9", &NoProgress).unwrap();
    let mut after = tree(&folder);
    for a in [LAUNCHER_EXE_NAME, UNLOCK_CMD_NAME, LOCK_CMD_NAME, UNLOCK_COMMAND_NAME, LOCK_COMMAND_NAME] {
        assert!(folder.join(a).exists(), "{a} must survive an unlock");
        after.remove(a);
    }
    assert_eq!(after, before, "user contents changed across the cycle");
}

#[test]
fn a_mac_binary_left_by_another_platform_is_treated_as_an_artefact() {
    use vaultdrive_lib::vault::{LAUNCHER_MAC_NAME, OpenVault, IN_PLACE_VAULT_NAME};

    // Stand in for a folder that a Mac has locked before: it carries the Mac
    // binary. A Windows lock must neither encrypt it nor delete it.
    let fx = Fixture::new();
    let folder = sample(&fx);
    let fake_mac = folder.join(LAUNCHER_MAC_NAME);
    fs::write(&fake_mac, b"\xcf\xfa\xed\xfe not really a Mach-O").unwrap();

    lock_with_launchers(&folder, "pw").unwrap();
    assert!(fake_mac.exists(), "the Mac binary must survive a Windows lock");
    let v = OpenVault::unlock(&folder.join(IN_PLACE_VAULT_NAME), b"pw").unwrap();
    let names: Vec<String> = v.index().nodes.iter().map(|n| n.name.clone()).collect();
    assert!(!names.iter().any(|n| n == LAUNCHER_MAC_NAME), "{names:?}");
    drop(v);

    unlock_folder_in_place(&folder, b"pw", &NoProgress).unwrap();
    assert!(fake_mac.exists(), "the Mac binary must survive an unlock");
}

#[test]
fn launchers_are_never_encrypted_into_the_vault_on_a_relock() {
    use vaultdrive_lib::vault::{LAUNCHER_EXE_NAME, OpenVault, IN_PLACE_VAULT_NAME};

    let fx = Fixture::new();
    let folder = sample(&fx);
    lock_with_launchers(&folder, "pw").unwrap();
    unlock_folder_in_place(&folder, b"pw", &NoProgress).unwrap();
    // Second lock: the exe and cmds are already sitting in the folder.
    lock_with_launchers(&folder, "pw").unwrap();

    let v = OpenVault::unlock(&folder.join(IN_PLACE_VAULT_NAME), b"pw").unwrap();
    let names: Vec<String> = v.index().nodes.iter().map(|n| n.name.clone()).collect();
    assert!(!names.iter().any(|n| n.eq_ignore_ascii_case(LAUNCHER_EXE_NAME)), "{names:?}");
    assert!(!names.iter().any(|n| n.ends_with(".cmd") || n.ends_with(".command")), "{names:?}");
    assert_eq!(v.index().stats().0, 4, "only the four user files belong in the vault");
}

/// Every file under `root`, as `relative path -> contents`.
fn tree(root: &Path) -> std::collections::BTreeMap<String, Vec<u8>> {
    walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| {
            let rel = e.path().strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
            (rel, fs::read(e.path()).unwrap())
        })
        .collect()
}

#[test]
fn locking_leaves_the_folder_in_place_holding_only_the_container() {
    let fx = Fixture::new();
    let folder = sample(&fx);
    lock(&folder, "pw").unwrap();

    assert!(folder.is_dir(), "the folder itself must survive");
    assert!(folder.join(IN_PLACE_VAULT_NAME).is_file());
    assert!(folder.join(IN_PLACE_README_NAME).is_file());

    let left: Vec<String> = fs::read_dir(&folder)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(left.len(), 2, "only the vault and the note should remain: {left:?}");
    assert!(!folder.join("notes.txt").exists());
    assert!(!folder.join("Documents").exists());
    assert!(!folder.join("Photos").exists());
}

#[test]
fn a_locked_folder_round_trips_byte_for_byte() {
    let fx = Fixture::new();
    let folder = sample(&fx);
    let before = tree(&folder);
    assert_eq!(before.len(), 4);

    lock(&folder, "a good long passphrase").unwrap();
    unlock_folder_in_place(&folder, b"a good long passphrase", &NoProgress).unwrap();

    assert_eq!(tree(&folder), before, "contents changed across a lock/unlock cycle");
    assert!(!folder.join(IN_PLACE_VAULT_NAME).exists(), "the container should be gone");
    assert!(!folder.join(IN_PLACE_README_NAME).exists());
    assert!(folder.join("Photos/2024").is_dir(), "empty-ish nesting must come back");
}

#[test]
fn the_folder_reports_its_state() {
    let fx = Fixture::new();
    let folder = sample(&fx);
    assert_eq!(folder_lock_state(&folder), FolderLockState::Unlocked);

    lock(&folder, "pw").unwrap();
    assert_eq!(folder_lock_state(&folder), FolderLockState::Locked);

    unlock_folder_in_place(&folder, b"pw", &NoProgress).unwrap();
    assert_eq!(folder_lock_state(&folder), FolderLockState::Unlocked);

    let empty = fx.path("Empty");
    fs::create_dir_all(&empty).unwrap();
    assert_eq!(folder_lock_state(&empty), FolderLockState::Empty);
    assert_eq!(folder_lock_state(&fx.path("nope")), FolderLockState::Unavailable);
}

#[test]
fn no_plaintext_survives_in_the_locked_folder() {
    let fx = Fixture::new();
    let marker = b"PAYROLL-MARKER-4471";
    let folder = fx.source(
        "Secret",
        &[("payroll.csv", &marker.repeat(200)), ("Reports/q3.txt", marker)],
    );
    lock(&folder, "pw").unwrap();

    for entry in walkdir::WalkDir::new(&folder).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        let data = fs::read(entry.path()).unwrap();
        assert!(
            !data.windows(marker.len()).any(|w| w == marker),
            "plaintext found in {}",
            entry.path().display()
        );
    }

    // Nor do the names.
    let vault = fs::read(folder.join(IN_PLACE_VAULT_NAME)).unwrap();
    for name in [&b"payroll"[..], b"Reports", b"q3", b".csv"] {
        assert!(
            !vault.windows(name.len()).any(|w| w == name),
            "the container leaks {:?}",
            String::from_utf8_lossy(name)
        );
    }
}

#[test]
fn the_wrong_password_does_not_unlock_and_changes_nothing() {
    let fx = Fixture::new();
    let folder = sample(&fx);
    lock(&folder, "the right one").unwrap();
    let locked_bytes = fs::read(folder.join(IN_PLACE_VAULT_NAME)).unwrap();

    let err = unlock_folder_in_place(&folder, b"the wrong one", &NoProgress).unwrap_err();
    assert!(matches!(err, VaultError::Authentication));

    assert_eq!(
        fs::read(folder.join(IN_PLACE_VAULT_NAME)).unwrap(),
        locked_bytes,
        "a failed unlock must not touch the container"
    );
    assert!(!folder.join("notes.txt").exists(), "nothing should have been restored");
    assert_eq!(folder_lock_state(&folder), FolderLockState::Locked);
}

#[test]
fn locking_an_already_locked_folder_is_refused() {
    let fx = Fixture::new();
    let folder = sample(&fx);
    lock(&folder, "pw").unwrap();
    let before = fs::read(folder.join(IN_PLACE_VAULT_NAME)).unwrap();

    let err = lock(&folder, "another password").unwrap_err();
    assert!(matches!(err, VaultError::AlreadyExists { .. }), "got {err:?}");
    assert_eq!(
        fs::read(folder.join(IN_PLACE_VAULT_NAME)).unwrap(),
        before,
        "the second attempt must not overwrite the first vault"
    );
}

#[test]
fn an_empty_folder_is_refused_rather_than_locked_into_nothing() {
    let fx = Fixture::new();
    let folder = fx.path("Empty");
    fs::create_dir_all(&folder).unwrap();
    assert!(matches!(lock(&folder, "pw"), Err(VaultError::InvalidInput(_))));
    assert!(!folder.join(IN_PLACE_VAULT_NAME).exists());
}

#[test]
fn an_empty_password_is_refused_and_nothing_is_deleted() {
    let fx = Fixture::new();
    let folder = sample(&fx);
    let before = tree(&folder);

    assert!(matches!(lock(&folder, ""), Err(VaultError::InvalidInput(_))));
    assert_eq!(tree(&folder), before, "the folder must be untouched");
    assert!(!folder.join(IN_PLACE_VAULT_NAME).exists());
}

#[test]
fn unlocking_a_folder_that_was_never_locked_is_refused() {
    let fx = Fixture::new();
    let folder = sample(&fx);
    let before = tree(&folder);
    assert!(matches!(
        unlock_folder_in_place(&folder, b"pw", &NoProgress),
        Err(VaultError::InvalidInput(_))
    ));
    assert_eq!(tree(&folder), before);
}

#[test]
fn a_locked_folder_survives_being_moved_to_another_path() {
    let fx = Fixture::new();
    let folder = sample(&fx);
    let before = tree(&folder);
    lock(&folder, "pw").unwrap();

    // Standing in for carrying the drive elsewhere: the whole folder moves.
    let moved = fx.path("Somewhere Else");
    fs::create_dir_all(&moved).unwrap();
    let moved = moved.join("Renamed Folder");
    fs::rename(&folder, &moved).unwrap();

    assert_eq!(folder_lock_state(&moved), FolderLockState::Locked);
    unlock_folder_in_place(&moved, b"pw", &NoProgress).unwrap();
    assert_eq!(tree(&moved), before);
}

#[test]
fn a_second_lock_after_unlocking_works_and_leaves_no_stale_artefacts() {
    let fx = Fixture::new();
    let folder = sample(&fx);
    let before = tree(&folder);

    for _ in 0..3 {
        lock(&folder, "pw").unwrap();
        assert_eq!(folder_lock_state(&folder), FolderLockState::Locked);
        unlock_folder_in_place(&folder, b"pw", &NoProgress).unwrap();
        assert_eq!(tree(&folder), before, "a cycle changed the contents");
    }

    let leftovers: Vec<_> = walkdir::WalkDir::new(&folder)
        .into_iter()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".vdtmp") || n.ends_with(".vdpart"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

#[test]
fn a_tampered_container_refuses_to_unlock_and_keeps_the_folder_locked() {
    let fx = Fixture::new();
    let folder = sample(&fx);
    lock(&folder, "pw").unwrap();

    let vault = folder.join(IN_PLACE_VAULT_NAME);
    let mut bytes = fs::read(&vault).unwrap();
    let n = bytes.len();
    bytes[n - 40] ^= 0x01;
    fs::write(&vault, &bytes).unwrap();

    let err = unlock_folder_in_place(&folder, b"pw", &NoProgress).unwrap_err();
    assert!(
        matches!(err, VaultError::Integrity | VaultError::Truncated | VaultError::Authentication),
        "got {err:?}"
    );
    assert!(!folder.join("notes.txt").exists(), "nothing may be half-restored");
}

#[test]
fn the_note_left_behind_explains_the_situation_and_holds_no_secret() {
    let fx = Fixture::new();
    let folder = sample(&fx);
    lock(&folder, "hunter2 correct horse").unwrap();

    let note = fs::read_to_string(folder.join(IN_PLACE_README_NAME)).unwrap();
    assert!(note.contains("locked by VaultDrive"));
    assert!(note.contains("no master password"));
    assert!(!note.contains("hunter2"));
    assert!(!note.to_lowercase().contains("correct horse"));
}

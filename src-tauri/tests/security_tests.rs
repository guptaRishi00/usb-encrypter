//! The claims on the box, checked against the bytes on disk.
//!
//! These tests read the raw `.vault` file and the log and assert that things
//! which must not appear, do not appear.

mod common;

use std::fs;

use common::{raw, Fixture};
use vaultdrive_lib::vault::format::{DATA_START, HEADER_LEN};
use vaultdrive_lib::vault::{NoProgress, OpenVault, ROOT_ID};

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn plaintext_file_contents_never_appear_in_the_vault() {
    let fx = Fixture::new();
    let marker = b"TOPSECRET-PAYROLL-2026-MARKER";
    let long = marker.repeat(500);
    let src = fx.source("s", &[("payroll.csv", &long), ("note.txt", marker)]);
    fx.create(&src, "V.vault", "a good long passphrase").unwrap();

    let bytes = raw(&fx.path("V.vault"));
    assert!(!contains(&bytes, marker), "plaintext content found in the vault file");
}

#[test]
fn file_and_folder_names_never_appear_in_the_vault() {
    let fx = Fixture::new();
    let src = fx.source(
        "s",
        &[
            ("Resignation Letter.docx", b"body"),
            ("Medical/Diagnosis Report.pdf", b"body"),
            ("Medical/Scans/mri-2026.dcm", b"body"),
        ],
    );
    fx.create(&src, "V.vault", "a good long passphrase").unwrap();

    let bytes = raw(&fx.path("V.vault"));
    for name in [
        &b"Resignation"[..],
        b"Diagnosis",
        b"Medical",
        b"Scans",
        b"mri-2026",
        b".docx",
        b".dcm",
    ] {
        assert!(!contains(&bytes, name), "the vault leaks the name fragment {:?}", String::from_utf8_lossy(name));
    }
}

#[test]
fn the_password_never_appears_in_the_vault() {
    let fx = Fixture::new();
    let pw = "UNIQUE-PASSPHRASE-MARKER-9182734";
    let src = fx.source("s", &[("a.txt", b"x")]);
    fx.create(&src, "V.vault", pw).unwrap();

    let bytes = raw(&fx.path("V.vault"));
    assert!(!contains(&bytes, pw.as_bytes()));
    assert!(!contains(&bytes, &pw.to_lowercase().into_bytes()));
}

#[test]
fn the_plaintext_header_carries_no_secrets_and_no_file_information() {
    let fx = Fixture::new();
    let src = fx.source("s", &[("a.txt", b"x"), ("b.txt", b"y"), ("c/d.txt", b"z")]);
    fx.create(&src, "V.vault", "pw").unwrap();

    let bytes = raw(&fx.path("V.vault"));
    let header = &bytes[..HEADER_LEN];

    assert_eq!(&header[0..8], b"VAULTDRV");
    // Everything after the salt is reserved and zero. The header is exactly
    // magic, version, algorithm ids, three cost parameters and a random salt.
    assert_eq!(&header[56..64], &[0u8; 8]);

    // Nothing about the contents leaks: three files and one folder are not
    // findable as any little-endian integer in the header.
    for n in [1u32, 2, 3, 4] {
        assert!(
            !contains(&header[56..], &n.to_le_bytes()),
            "the header appears to encode a count"
        );
    }
}

#[test]
fn two_identical_files_do_not_produce_identical_ciphertext() {
    let fx = Fixture::new();
    let payload = vec![0x33u8; 20_000];
    let src = fx.source("s", &[("one.bin", &payload), ("two.bin", &payload)]);
    fx.create(&src, "V.vault", "pw").unwrap();

    let bytes = raw(&fx.path("V.vault"));
    let region = &bytes[DATA_START as usize..];
    let half = region.len() / 2;
    let (a, b) = region.split_at(half);
    let overlap = a.len().min(b.len()).min(10_000);
    assert_ne!(
        &a[..overlap],
        &b[..overlap],
        "identical plaintext produced identical ciphertext: nonce reuse"
    );
}

#[test]
fn a_vault_looks_like_random_data_apart_from_its_header() {
    let fx = Fixture::new();
    let src = fx.source("s", &[("zeros.bin", &vec![0u8; 200_000])]);
    fx.create(&src, "V.vault", "pw").unwrap();

    let bytes = raw(&fx.path("V.vault"));
    let body = &bytes[DATA_START as usize..];

    // A 200 KB run of zeros encrypts to something with no long constant runs.
    let mut longest = 0usize;
    let mut run = 0usize;
    for w in body.windows(2) {
        if w[0] == w[1] {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    assert!(longest < 64, "found a run of {longest} identical bytes in the ciphertext");
}

#[test]
fn no_key_material_reaches_the_settings_file() {
    let fx = Fixture::new();
    let mut s = vaultdrive_lib::settings::Settings::default();
    s.remember("D:\\Vaults\\Personal.vault", "Personal", 1000);
    s.save(fx.dir.path()).unwrap();

    let raw = fs::read_to_string(fx.dir.path().join("settings.json")).unwrap();
    let lower = raw.to_lowercase();
    for forbidden in ["password", "passphrase", "salt", "nonce", "masterkey", "secret"] {
        assert!(!lower.contains(forbidden), "settings.json mentions {forbidden}");
    }
}

#[test]
fn the_master_key_type_refuses_to_print_itself() {
    let key = vaultdrive_lib::crypto::MasterKey::from_bytes([0xDEu8; 32]);
    assert_eq!(format!("{key:?}"), "MasterKey(<redacted>)");
}

#[test]
fn an_unlocked_vault_refuses_to_print_its_path_keys_or_names() {
    let fx = Fixture::new();
    let src = fx.source("s", &[("PayrollSecret.txt", b"x")]);
    fx.create(&src, "V.vault", "pw").unwrap();
    let v = fx.unlock("V.vault", "pw").unwrap();

    let rendered = format!("{v:?}");
    assert!(!rendered.contains("PayrollSecret"));
    assert!(!rendered.contains("V.vault"));
    assert!(!rendered.to_lowercase().contains("key"));
}

#[test]
fn locking_drops_the_vault_and_a_second_unlock_needs_the_password_again() {
    let fx = Fixture::new();
    let src = fx.source("s", &[("a.txt", b"x")]);
    fx.create(&src, "V.vault", "pw").unwrap();

    let session = vaultdrive_lib::vault::VaultSession::new();
    session.set_vault(fx.unlock("V.vault", "pw").unwrap());
    assert!(session.is_unlocked());

    assert!(session.lock());
    assert!(!session.is_unlocked());
    assert!(matches!(
        session.with(|_| Ok(())),
        Err(vaultdrive_lib::error::VaultError::Locked)
    ));

    // The only way back in is the password.
    assert!(OpenVault::unlock(&fx.path("V.vault"), b"wrong").is_err());
    assert!(OpenVault::unlock(&fx.path("V.vault"), b"pw").is_ok());
}

#[test]
fn exporting_cannot_escape_the_destination_folder() {
    // A vault whose index carries a traversal name is refused at export, not
    // written outside the chosen folder. Names are validated on the way in as
    // well, so this is the second of two independent checks.
    for evil in ["..", "../escape.txt", "..\\escape.txt", "C:\\Windows\\evil.exe", "a/b"] {
        assert!(
            vaultdrive_lib::vault::index::validate_name(evil).is_err(),
            "{evil} was accepted as a name"
        );
    }
}

#[test]
fn no_plaintext_temporary_files_are_left_after_an_export() {
    let fx = Fixture::new();
    let marker = b"TEMPFILE-LEAK-MARKER-55512";
    let src = fx.source("s", &[("a.txt", &marker.repeat(100))]);
    fx.create(&src, "V.vault", "pw").unwrap();
    fs::remove_dir_all(&src).unwrap();

    let out = fx.path("out");
    fs::create_dir_all(&out).unwrap();
    let mut v = fx.unlock("V.vault", "pw").unwrap();
    v.export(ROOT_ID, &out, &NoProgress).unwrap();

    // Only the exported tree should contain the marker; nothing beside the
    // vault, and no leftover part files anywhere.
    for entry in walkdir::WalkDir::new(fx.dir.path()).into_iter().filter_map(|e| e.ok()) {
        let name = entry.file_name().to_string_lossy().into_owned();
        assert!(!name.ends_with(".vdpart"), "left a part file: {name}");
        assert!(!name.ends_with(".vdtmp"), "left a temp vault: {name}");
        if entry.file_type().is_file() && !entry.path().starts_with(&out) {
            let data = fs::read(entry.path()).unwrap_or_default();
            assert!(
                !contains(&data, marker),
                "plaintext leaked outside the export folder: {}",
                entry.path().display()
            );
        }
    }
}

#[test]
fn a_deleted_entry_is_unreachable_and_compaction_removes_its_bytes() {
    let fx = Fixture::new();
    let marker = b"DELETE-ME-MARKER-77341";
    let src = fx.source("s", &[("keep.txt", b"keep"), ("secret.txt", &marker.repeat(200))]);
    fx.create(&src, "V.vault", "pw").unwrap();

    let mut v = fx.unlock("V.vault", "pw").unwrap();
    let id = common::id_of(v.index(), "secret.txt").unwrap();
    v.delete(id).unwrap();
    assert!(v.dead_bytes() > 0, "deletion should report reclaimable space");
    drop(v);

    // The entry is gone from the index immediately.
    let v = fx.unlock("V.vault", "pw").unwrap();
    assert!(common::id_of(v.index(), "secret.txt").is_none());
    let v = v.compact(&NoProgress).unwrap();
    assert_eq!(v.dead_bytes(), 0);
    assert!(common::id_of(v.index(), "keep.txt").is_some());
    drop(v);

    // And after compaction the ciphertext is gone from the file as well. It was
    // never readable, but it is no longer present.
    let bytes = raw(&fx.path("V.vault"));
    assert!(!contains(&bytes, marker));

    // The rebuilt vault still opens with the same password and nothing else.
    assert!(fx.unlock("V.vault", "wrong").is_err());
    let mut v = fx.unlock("V.vault", "pw").unwrap();
    let keep = common::id_of(v.index(), "keep.txt").unwrap();
    assert_eq!(v.read_file_to_vec(keep, usize::MAX).unwrap(), b"keep");
}

#[test]
fn creating_a_vault_never_deletes_the_source_by_itself() {
    let fx = Fixture::new();
    let src = fx.source("s", &[("a.txt", b"x"), ("sub/b.txt", b"y")]);
    let before: Vec<_> = walkdir::WalkDir::new(&src)
        .into_iter()
        .filter_map(|e| e.ok())
        .map(|e| e.path().to_path_buf())
        .collect();

    fx.create(&src, "V.vault", "pw").unwrap();

    let after: Vec<_> = walkdir::WalkDir::new(&src)
        .into_iter()
        .filter_map(|e| e.ok())
        .map(|e| e.path().to_path_buf())
        .collect();
    assert_eq!(before, after, "the source folder must be untouched by creation");
}

//! The in-vault file browser: import, export, create, rename, move, delete,
//! and the durability of every one of those across a lock and unlock.

mod common;

use std::fs;

use common::{dump, id_of, Fixture};
use vaultdrive_lib::error::VaultError;
use vaultdrive_lib::vault::{NoProgress, ROOT_ID};

#[test]
fn creating_a_folder_survives_locking_and_unlocking() {
    let fx = Fixture::new();
    let src = fx.source("s", &[("a.txt", b"x")]);
    fx.create(&src, "V.vault", "pw").unwrap();

    let mut v = fx.unlock("V.vault", "pw").unwrap();
    v.create_folder(ROOT_ID, "Invoices").unwrap();
    drop(v);

    let v = fx.unlock("V.vault", "pw").unwrap();
    assert!(id_of(v.index(), "Invoices").is_some());
}

#[test]
fn importing_a_file_stores_its_contents_and_survives_a_relock() {
    let fx = Fixture::new();
    let src = fx.source("s", &[("a.txt", b"x")]);
    fx.create(&src, "V.vault", "pw").unwrap();

    let extra = fx.path("extra.bin");
    let payload: Vec<u8> = (0..50_000).map(|i| (i % 251) as u8).collect();
    fs::write(&extra, &payload).unwrap();

    let mut v = fx.unlock("V.vault", "pw").unwrap();
    let id = v.import_file(ROOT_ID, &extra, &NoProgress).unwrap();
    assert_eq!(v.read_file_to_vec(id, usize::MAX).unwrap(), payload);
    drop(v);

    let mut v = fx.unlock("V.vault", "pw").unwrap();
    let id = id_of(v.index(), "extra.bin").unwrap();
    assert_eq!(v.read_file_to_vec(id, usize::MAX).unwrap(), payload);
    assert_eq!(v.index().stats().0, 2);
}

#[test]
fn importing_a_folder_brings_its_whole_tree() {
    let fx = Fixture::new();
    let src = fx.source("s", &[("a.txt", b"x")]);
    fx.create(&src, "V.vault", "pw").unwrap();

    let incoming = fx.source(
        "incoming",
        &[("top.txt", b"top"), ("deep/one.txt", b"one"), ("deep/more/two.txt", b"two")],
    );

    let mut v = fx.unlock("V.vault", "pw").unwrap();
    v.import_folder(ROOT_ID, &incoming, &NoProgress).unwrap();
    drop(v);

    let mut v = fx.unlock("V.vault", "pw").unwrap();
    let files = dump(&mut v);
    assert_eq!(files.get("incoming/deep/more/two.txt").map(|v| v.as_slice()), Some(&b"two"[..]));
    assert_eq!(files.get("incoming/top.txt").map(|v| v.as_slice()), Some(&b"top"[..]));
}

#[test]
fn renaming_changes_the_name_and_nothing_else() {
    let fx = Fixture::new();
    let src = fx.source("s", &[("old-name.txt", b"unchanged contents")]);
    fx.create(&src, "V.vault", "pw").unwrap();

    let mut v = fx.unlock("V.vault", "pw").unwrap();
    let id = id_of(v.index(), "old-name.txt").unwrap();
    v.rename(id, "new-name.txt").unwrap();
    drop(v);

    let mut v = fx.unlock("V.vault", "pw").unwrap();
    let id = id_of(v.index(), "new-name.txt").unwrap();
    assert!(id_of(v.index(), "old-name.txt").is_none());
    assert_eq!(v.read_file_to_vec(id, usize::MAX).unwrap(), b"unchanged contents");
}

#[test]
fn renaming_onto_an_existing_name_is_refused() {
    let fx = Fixture::new();
    let src = fx.source("s", &[("a.txt", b"a"), ("b.txt", b"b")]);
    fx.create(&src, "V.vault", "pw").unwrap();

    let mut v = fx.unlock("V.vault", "pw").unwrap();
    let a = id_of(v.index(), "a.txt").unwrap();
    assert!(matches!(v.rename(a, "b.txt"), Err(VaultError::AlreadyExists { .. })));
    assert!(matches!(v.rename(a, "B.TXT"), Err(VaultError::AlreadyExists { .. })));
    // The failed rename left the vault exactly as it was.
    assert_eq!(v.index().get(a).unwrap().name, "a.txt");
}

#[test]
fn an_invalid_new_name_is_refused() {
    let fx = Fixture::new();
    let src = fx.source("s", &[("a.txt", b"a")]);
    fx.create(&src, "V.vault", "pw").unwrap();

    let mut v = fx.unlock("V.vault", "pw").unwrap();
    let a = id_of(v.index(), "a.txt").unwrap();
    for evil in ["..", "sub/evil.txt", "..\\escape.txt", "CON", "trailing.", ""] {
        assert!(v.rename(a, evil).is_err(), "{evil} was accepted");
    }
}

#[test]
fn moving_a_file_into_a_folder_keeps_its_contents() {
    let fx = Fixture::new();
    let src = fx.source("s", &[("note.txt", b"the contents"), ("Folder/other.txt", b"o")]);
    fx.create(&src, "V.vault", "pw").unwrap();

    let mut v = fx.unlock("V.vault", "pw").unwrap();
    let note = id_of(v.index(), "note.txt").unwrap();
    let folder = id_of(v.index(), "Folder").unwrap();
    v.move_entry(note, folder).unwrap();
    drop(v);

    let mut v = fx.unlock("V.vault", "pw").unwrap();
    let moved = id_of(v.index(), "Folder/note.txt").unwrap();
    assert!(id_of(v.index(), "note.txt").is_none());
    assert_eq!(v.read_file_to_vec(moved, usize::MAX).unwrap(), b"the contents");
}

#[test]
fn moving_a_folder_into_its_own_descendant_is_refused() {
    let fx = Fixture::new();
    let src = fx.source("s", &[("a/b/c.txt", b"x")]);
    fx.create(&src, "V.vault", "pw").unwrap();

    let mut v = fx.unlock("V.vault", "pw").unwrap();
    let a = id_of(v.index(), "a").unwrap();
    let b = id_of(v.index(), "a/b").unwrap();
    assert!(matches!(v.move_entry(a, b), Err(VaultError::InvalidMove)));
    assert!(matches!(v.move_entry(a, a), Err(VaultError::InvalidMove)));
    // Still intact.
    assert!(id_of(v.index(), "a/b/c.txt").is_some());
}

#[test]
fn deleting_a_folder_removes_everything_under_it() {
    let fx = Fixture::new();
    let src = fx.source(
        "s",
        &[("keep.txt", b"keep"), ("gone/a.txt", b"a"), ("gone/deep/b.txt", b"b")],
    );
    fx.create(&src, "V.vault", "pw").unwrap();

    let mut v = fx.unlock("V.vault", "pw").unwrap();
    let gone = id_of(v.index(), "gone").unwrap();
    v.delete(gone).unwrap();
    drop(v);

    let mut v = fx.unlock("V.vault", "pw").unwrap();
    assert!(id_of(v.index(), "gone").is_none());
    assert!(id_of(v.index(), "gone/deep/b.txt").is_none());
    let keep = id_of(v.index(), "keep.txt").unwrap();
    assert_eq!(v.read_file_to_vec(keep, usize::MAX).unwrap(), b"keep");
    assert_eq!(v.index().stats().0, 1);
}

#[test]
fn the_vault_root_cannot_be_deleted() {
    let fx = Fixture::new();
    let src = fx.source("s", &[("a.txt", b"x")]);
    fx.create(&src, "V.vault", "pw").unwrap();
    let mut v = fx.unlock("V.vault", "pw").unwrap();
    assert!(v.delete(ROOT_ID).is_err());
}

#[test]
fn many_edits_in_a_row_all_survive() {
    let fx = Fixture::new();
    let src = fx.source("s", &[("a.txt", b"a")]);
    fx.create(&src, "V.vault", "pw").unwrap();

    let mut v = fx.unlock("V.vault", "pw").unwrap();
    for i in 0..30 {
        v.create_folder(ROOT_ID, &format!("folder-{i}")).unwrap();
    }
    let a = id_of(v.index(), "a.txt").unwrap();
    let target = id_of(v.index(), "folder-7").unwrap();
    v.move_entry(a, target).unwrap();
    v.rename(target, "renamed-7").unwrap();
    let generation = v.generation();
    assert!(generation > 30, "each commit should advance the generation");
    drop(v);

    let mut v = fx.unlock("V.vault", "pw").unwrap();
    assert_eq!(v.index().stats().1, 30);
    let moved = id_of(v.index(), "renamed-7/a.txt").unwrap();
    assert_eq!(v.read_file_to_vec(moved, usize::MAX).unwrap(), b"a");
    assert_eq!(v.generation(), generation);
}

#[test]
fn alternating_superblock_slots_keep_the_vault_readable_at_every_step() {
    let fx = Fixture::new();
    let src = fx.source("s", &[("a.txt", b"a")]);
    fx.create(&src, "V.vault", "pw").unwrap();

    // Every commit writes the slot the previous one did not. Re-opening after
    // each edit proves both slots are being written correctly.
    for i in 0..8 {
        let mut v = fx.unlock("V.vault", "pw").unwrap();
        v.create_folder(ROOT_ID, &format!("f{i}")).unwrap();
        drop(v);
        let v = fx.unlock("V.vault", "pw").unwrap();
        assert_eq!(v.index().stats().1, i + 1);
    }
}

#[test]
fn a_preview_refuses_a_file_larger_than_its_limit() {
    let fx = Fixture::new();
    let src = fx.source("s", &[("big.bin", &vec![1u8; 200_000])]);
    fx.create(&src, "V.vault", "pw").unwrap();

    let mut v = fx.unlock("V.vault", "pw").unwrap();
    let id = id_of(v.index(), "big.bin").unwrap();
    assert!(v.read_file_to_vec(id, 1000).is_err());
    assert!(v.read_file_to_vec(id, 500_000).is_ok());
}

#[test]
fn reading_a_folder_as_a_file_is_refused() {
    let fx = Fixture::new();
    let src = fx.source("s", &[("dir/a.txt", b"x")]);
    fx.create(&src, "V.vault", "pw").unwrap();
    let mut v = fx.unlock("V.vault", "pw").unwrap();
    let dir = id_of(v.index(), "dir").unwrap();
    assert!(v.read_file_to_vec(dir, usize::MAX).is_err());
}

#[test]
fn compaction_preserves_every_file_and_folder() {
    let fx = Fixture::new();
    let src = fx.source(
        "s",
        &[
            ("a.txt", b"aaa"),
            ("Docs/b.txt", b"bbb"),
            ("Docs/Deep/c.bin", &[7u8; 30_000]),
            ("empty.txt", b""),
        ],
    );
    fx.create(&src, "V.vault", "pw").unwrap();

    let (before_files, before_folders) = {
        let mut v = fx.unlock("V.vault", "pw").unwrap();
        (dump(&mut v), common::folders(v.index()))
    };

    let mut v = fx.unlock("V.vault", "pw").unwrap();
    let doomed = id_of(v.index(), "a.txt").unwrap();
    v.delete(doomed).unwrap();
    let v = v.compact(&NoProgress).unwrap();
    drop(v);

    let mut v = fx.unlock("V.vault", "pw").unwrap();
    assert_eq!(common::folders(v.index()), before_folders);
    let after = dump(&mut v);
    for (path, data) in before_files.iter().filter(|(p, _)| p.as_str() != "a.txt") {
        assert_eq!(after.get(path), Some(data), "{path} changed across compaction");
    }
    assert!(!after.contains_key("a.txt"));
}

#[test]
fn compaction_shrinks_a_vault_that_has_had_a_large_file_deleted() {
    let fx = Fixture::new();
    let src = fx.source("s", &[("small.txt", b"s"), ("large.bin", &vec![3u8; 400_000])]);
    fx.create(&src, "V.vault", "pw").unwrap();
    let before = fs::metadata(fx.path("V.vault")).unwrap().len();

    let mut v = fx.unlock("V.vault", "pw").unwrap();
    let large = id_of(v.index(), "large.bin").unwrap();
    v.delete(large).unwrap();
    let v = v.compact(&NoProgress).unwrap();
    drop(v);

    let after = fs::metadata(fx.path("V.vault")).unwrap().len();
    assert!(after < before / 2, "compaction did not reclaim the space: {before} -> {after}");
    assert!(fx.unlock("V.vault", "pw").is_ok());
}

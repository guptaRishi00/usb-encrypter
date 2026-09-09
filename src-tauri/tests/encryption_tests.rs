//! Encryption round trips: does everything that goes in come back out exactly?

mod common;

use std::collections::BTreeMap;
use std::fs;

use common::{dump, folders, id_of, Fixture};
use vaultdrive_lib::crypto::aead::CHUNK_SIZE;
use vaultdrive_lib::vault::NoProgress;

fn expect(pairs: &[(&str, &[u8])]) -> BTreeMap<String, Vec<u8>> {
    pairs.iter().map(|(k, v)| ((*k).to_string(), v.to_vec())).collect()
}

#[test]
fn a_nested_tree_round_trips_byte_for_byte() {
    let fx = Fixture::new();
    let files: &[(&str, &[u8])] = &[
        ("notes.txt", b"top level note"),
        ("Documents/Resume.pdf", b"%PDF-1.7 fake resume"),
        ("Documents/Certificate.pdf", b"%PDF-1.7 fake certificate"),
        ("Photos/photo1.jpg", &[0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10]),
        ("Photos/2024/photo2.png", &[0x89, 0x50, 0x4E, 0x47]),
    ];
    let src = fx.source("MySecretFolder", files);

    let report = fx.create(&src, "MyVault.vault", "pw").unwrap();
    assert_eq!(report.files, 5);
    assert_eq!(report.folders, 3);
    assert!(report.verified, "creation must confirm the vault reopens");
    assert!(report.skipped.is_empty());

    let mut v = fx.unlock("MyVault.vault", "pw").unwrap();
    assert_eq!(dump(&mut v), expect(files));
    assert_eq!(
        folders(v.index()),
        ["Documents", "Photos", "Photos/2024"].iter().map(|s| s.to_string()).collect()
    );
}

#[test]
fn an_empty_file_round_trips() {
    let fx = Fixture::new();
    let src = fx.source("s", &[("empty.bin", b""), ("nonempty.bin", b"x")]);
    fx.create(&src, "V.vault", "pw").unwrap();

    let mut v = fx.unlock("V.vault", "pw").unwrap();
    let id = id_of(v.index(), "empty.bin").unwrap();
    assert_eq!(v.index().get(id).unwrap().size, 0);
    assert_eq!(v.read_file_to_vec(id, usize::MAX).unwrap(), Vec::<u8>::new());
}

#[test]
fn an_empty_folder_is_preserved() {
    let fx = Fixture::new();
    let src = fx.source("s", &[("keep/a.txt", b"a")]);
    fs::create_dir_all(src.join("empty-one/empty-two")).unwrap();
    fx.create(&src, "V.vault", "pw").unwrap();

    let v = fx.unlock("V.vault", "pw").unwrap();
    let f = folders(v.index());
    assert!(f.contains("empty-one"));
    assert!(f.contains("empty-one/empty-two"));
}

#[test]
fn binary_content_including_every_byte_value_round_trips() {
    let fx = Fixture::new();
    let all_bytes: Vec<u8> = (0..=255u8).cycle().take(70_000).collect();
    let src = fx.source("s", &[("blob.bin", &all_bytes)]);
    fx.create(&src, "V.vault", "pw").unwrap();

    let mut v = fx.unlock("V.vault", "pw").unwrap();
    let id = id_of(v.index(), "blob.bin").unwrap();
    assert_eq!(v.read_file_to_vec(id, usize::MAX).unwrap(), all_bytes);
}

#[test]
fn a_file_larger_than_one_chunk_round_trips() {
    let fx = Fixture::new();
    // Two full chunks plus a remainder exercises next(), next() and last().
    let big: Vec<u8> = (0..(CHUNK_SIZE * 2 + 4321)).map(|i| (i % 251) as u8).collect();
    let src = fx.source("s", &[("big.bin", &big)]);
    fx.create(&src, "V.vault", "pw").unwrap();

    let mut v = fx.unlock("V.vault", "pw").unwrap();
    let id = id_of(v.index(), "big.bin").unwrap();
    assert_eq!(v.index().get(id).unwrap().size, big.len() as u64);
    assert_eq!(v.read_file_to_vec(id, usize::MAX).unwrap(), big);
}

#[test]
fn a_file_exactly_one_chunk_long_round_trips() {
    let fx = Fixture::new();
    let exact = vec![0xA7u8; CHUNK_SIZE];
    let src = fx.source("s", &[("exact.bin", &exact)]);
    fx.create(&src, "V.vault", "pw").unwrap();

    let mut v = fx.unlock("V.vault", "pw").unwrap();
    let id = id_of(v.index(), "exact.bin").unwrap();
    assert_eq!(v.read_file_to_vec(id, usize::MAX).unwrap(), exact);
}

#[test]
fn streaming_a_large_file_does_not_buffer_the_whole_thing() {
    let fx = Fixture::new();
    let big: Vec<u8> = (0..(CHUNK_SIZE * 3)).map(|i| (i % 97) as u8).collect();
    let src = fx.source("s", &[("big.bin", &big)]);
    fx.create(&src, "V.vault", "pw").unwrap();

    let mut v = fx.unlock("V.vault", "pw").unwrap();
    let id = id_of(v.index(), "big.bin").unwrap();

    let mut chunks = Vec::new();
    let mut total = 0usize;
    v.read_file(id, |c| {
        chunks.push(c.len());
        total += c.len();
        Ok(())
    })
    .unwrap();

    assert_eq!(total, big.len());
    assert!(chunks.len() >= 3, "a three-chunk file should arrive in at least three pieces");
    assert!(
        chunks.iter().all(|n| *n <= CHUNK_SIZE),
        "no single callback may exceed one chunk"
    );
}

#[test]
fn unicode_names_and_deep_nesting_round_trip() {
    let fx = Fixture::new();
    let files: &[(&str, &[u8])] = &[
        ("Fotos de Verão/履歴書.pdf", b"resume"),
        ("Fotos de Verão/Ελλάδα/σημειώσεις.txt", b"notes"),
        ("Ω/Ω/Ω/Ω/Ω/deep.txt", b"deep"),
        ("emoji 🔐 folder/file 📄.txt", b"emoji"),
    ];
    let src = fx.source("s", files);
    fx.create(&src, "V.vault", "pw").unwrap();

    let mut v = fx.unlock("V.vault", "pw").unwrap();
    assert_eq!(dump(&mut v), expect(files));
}

#[test]
fn timestamps_are_preserved_in_the_index() {
    let fx = Fixture::new();
    let src = fx.source("s", &[("a.txt", b"x")]);
    let expected = fs::metadata(src.join("a.txt"))
        .unwrap()
        .modified()
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    fx.create(&src, "V.vault", "pw").unwrap();
    let v = fx.unlock("V.vault", "pw").unwrap();
    let id = id_of(v.index(), "a.txt").unwrap();
    assert_eq!(v.index().get(id).unwrap().mtime, Some(expected));
}

#[test]
fn exported_files_carry_their_original_modification_time() {
    let fx = Fixture::new();
    let src = fx.source("s", &[("a.txt", b"x"), ("sub/b.txt", b"y")]);
    let original = fs::metadata(src.join("sub/b.txt")).unwrap().modified().unwrap();
    fx.create(&src, "V.vault", "pw").unwrap();

    let out = fx.path("restored");
    fs::create_dir_all(&out).unwrap();
    let mut v = fx.unlock("V.vault", "pw").unwrap();
    let root = v.export(vaultdrive_lib::vault::ROOT_ID, &out, &NoProgress).unwrap();

    let restored = fs::metadata(root.join("sub/b.txt")).unwrap().modified().unwrap();
    let a = original.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let b = restored.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    // The index stores whole seconds, so that is the resolution to compare at.
    assert_eq!(a, b, "the exported file should keep its original timestamp");
}

#[test]
fn exporting_recreates_the_original_tree_on_disk() {
    let fx = Fixture::new();
    let files: &[(&str, &[u8])] = &[
        ("notes.txt", b"note"),
        ("Documents/Resume.pdf", b"resume bytes"),
        ("Photos/2024/p.png", &[1, 2, 3, 4, 5]),
    ];
    let src = fx.source("MySecretFolder", files);
    fx.create(&src, "V.vault", "pw").unwrap();

    let out = fx.path("restored");
    fs::create_dir_all(&out).unwrap();
    let mut v = fx.unlock("V.vault", "pw").unwrap();
    let root = v.export(vaultdrive_lib::vault::ROOT_ID, &out, &NoProgress).unwrap();

    for (rel, data) in files {
        let p = root.join(rel);
        assert!(p.exists(), "{rel} was not restored");
        assert_eq!(&fs::read(&p).unwrap(), data, "{rel} came back different");
    }
    assert!(root.join("Photos/2024").is_dir());
}

#[test]
fn exporting_a_single_file_writes_only_that_file() {
    let fx = Fixture::new();
    let src = fx.source("s", &[("a.txt", b"aaa"), ("b.txt", b"bbb")]);
    fx.create(&src, "V.vault", "pw").unwrap();

    let out = fx.path("one");
    fs::create_dir_all(&out).unwrap();
    let mut v = fx.unlock("V.vault", "pw").unwrap();
    let id = id_of(v.index(), "a.txt").unwrap();
    let written = v.export(id, &out, &NoProgress).unwrap();

    assert_eq!(fs::read(&written).unwrap(), b"aaa");
    assert_eq!(fs::read_dir(&out).unwrap().count(), 1);
}

#[test]
fn an_export_leaves_no_part_files_behind() {
    let fx = Fixture::new();
    let src = fx.source("s", &[("a.txt", b"aaa"), ("sub/b.bin", &[7u8; 5000])]);
    fx.create(&src, "V.vault", "pw").unwrap();

    let out = fx.path("restored");
    fs::create_dir_all(&out).unwrap();
    let mut v = fx.unlock("V.vault", "pw").unwrap();
    let root = v.export(vaultdrive_lib::vault::ROOT_ID, &out, &NoProgress).unwrap();

    let leftovers: Vec<_> = walkdir::WalkDir::new(&root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".vdpart"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

#[test]
fn a_vault_with_a_thousand_files_round_trips() {
    let fx = Fixture::new();
    let root = fx.path("many");
    fs::create_dir_all(&root).unwrap();
    for i in 0..1000 {
        let dir = root.join(format!("d{}", i % 20));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(format!("f{i}.txt")), format!("contents of {i}")).unwrap();
    }

    let report = fx.create(&root, "Many.vault", "pw").unwrap();
    assert_eq!(report.files, 1000);
    assert_eq!(report.folders, 20);

    let mut v = fx.unlock("Many.vault", "pw").unwrap();
    assert_eq!(v.index().stats().0, 1000);
    let id = id_of(v.index(), "d3/f503.txt").unwrap();
    assert_eq!(v.read_file_to_vec(id, usize::MAX).unwrap(), b"contents of 503");
}

#[test]
fn a_vault_created_on_one_path_opens_after_being_copied_elsewhere() {
    let fx = Fixture::new();
    let src = fx.source("s", &[("a.txt", b"portable")]);
    fx.create(&src, "V.vault", "pw").unwrap();

    // Standing in for carrying the drive to another computer: the vault file is
    // the only thing that moves.
    let elsewhere = fx.path("another-machine");
    fs::create_dir_all(&elsewhere).unwrap();
    let moved = elsewhere.join("Renamed.vault");
    fs::copy(fx.path("V.vault"), &moved).unwrap();
    fs::remove_file(fx.path("V.vault")).unwrap();
    fs::remove_dir_all(&src).unwrap();

    let mut v = vaultdrive_lib::vault::OpenVault::unlock(&moved, b"pw").unwrap();
    let id = id_of(v.index(), "a.txt").unwrap();
    assert_eq!(v.read_file_to_vec(id, usize::MAX).unwrap(), b"portable");
}

//! Watch-only folders and the player's read path: any byte range of a stored
//! file can be decrypted on its own, authenticated, without restoring it.

mod common;

use std::fs;
use std::io::{Seek, SeekFrom, Write};

use common::{id_of, Fixture};
use vaultdrive_lib::error::VaultError;
use vaultdrive_lib::vault::{
    folder_lock_state, lock_folder_in_place, lock_folder_in_place_with, open_folder_vault,
    unlock_folder_in_place, unlock_folder_in_place_with, FolderLockState, NoProgress, OpenVault,
    IN_PLACE_VAULT_NAME,
};

const MB: usize = 1024 * 1024;

/// Bytes whose value depends on their position, so a slice from the wrong
/// place can never compare equal by accident.
fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| ((i * 31 + i / 7919) as u8).wrapping_add(seed)).collect()
}

#[test]
fn any_range_reads_back_exactly_across_chunk_boundaries() {
    let fx = Fixture::new();
    let film = pattern(3 * MB + 123, 1);
    let exact = pattern(2 * MB, 2);
    let tiny = pattern(10, 3);
    let src = fx.source(
        "Films",
        &[("film.mp4", &film), ("exact.mp4", &exact), ("tiny.mp4", &tiny), ("empty.mp4", b"")],
    );
    fx.create(&src, "films.vault", "gravel-tunnel-9").unwrap();
    let mut v = fx.unlock("films.vault", "gravel-tunnel-9").unwrap();
    let idx = v.index().clone();

    let cases: &[(&str, &Vec<u8>, &[(usize, usize)])] = &[
        (
            "film.mp4",
            &film,
            &[
                (0, 10),
                (MB - 5, 10),             // straddles chunk 0 and 1
                (2 * MB - 1, MB + 2),     // spans three chunks
                (3 * MB, 123),            // exactly the short final chunk
                (3 * MB + 120, 1000),     // runs past the end
                (0, 3 * MB + 123),        // the whole file
                (1_500_000, 4 * MB),      // more than is left
            ],
        ),
        ("exact.mp4", &exact, &[(2 * MB - 1, 1), (MB, MB), (0, 2 * MB)]),
        ("tiny.mp4", &tiny, &[(0, 10), (9, 1), (3, 100)]),
    ];
    for (name, data, ranges) in cases {
        let id = id_of(&idx, name).unwrap();
        for &(off, len) in *ranges {
            let got = v.read_range(id, off as u64, len).unwrap();
            let end = (off + len).min(data.len());
            assert_eq!(got, data[off..end], "{name} at {off}+{len}");
        }
        assert!(v.read_range(id, data.len() as u64, 10).unwrap().is_empty(), "{name} past end");
    }

    let empty = id_of(&idx, "empty.mp4").unwrap();
    assert!(v.read_range(empty, 0, 10).unwrap().is_empty());
}

#[test]
fn a_tampered_chunk_is_refused_and_its_neighbours_still_play() {
    let fx = Fixture::new();
    let film = pattern(3 * MB + 500, 9);
    let src = fx.source("Films", &[("film.mp4", &film)]);
    fx.create(&src, "films.vault", "gravel-tunnel-9").unwrap();

    let (id, offset) = {
        let v = fx.unlock("films.vault", "gravel-tunnel-9").unwrap();
        let id = id_of(v.index(), "film.mp4").unwrap();
        (id, v.index().get(id).unwrap().offset)
    };

    // Flip one byte inside the third chunk's ciphertext.
    let chunk_ct = (MB + 16) as u64;
    let mut f = fs::OpenOptions::new().read(true).write(true).open(fx.path("films.vault")).unwrap();
    f.seek(SeekFrom::Start(offset + 2 * chunk_ct + 1000)).unwrap();
    let mut b = [0u8; 1];
    std::io::Read::read_exact(&mut f, &mut b).unwrap();
    f.seek(SeekFrom::Current(-1)).unwrap();
    f.write_all(&[b[0] ^ 0x40]).unwrap();
    drop(f);

    let mut v = fx.unlock("films.vault", "gravel-tunnel-9").unwrap();
    assert!(matches!(v.read_range(id, 2 * MB as u64 + 10, 100), Err(VaultError::Integrity)));
    // A range that only partly touches the bad chunk is refused whole.
    assert!(matches!(v.read_range(id, 2 * MB as u64 - 10, 100), Err(VaultError::Integrity)));
    // Chunks that were not touched still decrypt: seeking past damage works.
    assert_eq!(v.read_range(id, 0, 100).unwrap(), film[..100]);
    assert_eq!(v.read_range(id, 3 * MB as u64, 500).unwrap(), film[3 * MB..]);
}

#[test]
fn a_watch_only_folder_plays_but_the_travelling_program_cannot_restore_it() {
    let fx = Fixture::new();
    let film = pattern(MB + 77, 4);
    let folder = fx.source("Movie Night", &[("film.mp4", &film), ("notes.txt", b"popcorn")]);

    lock_folder_in_place_with(
        &folder,
        b"gravel-tunnel-9",
        common::fast_kdf(),
        false,
        true,
        &NoProgress,
    )
    .unwrap();
    assert_eq!(folder_lock_state(&folder), FolderLockState::Locked);

    // The program in the folder, and its launchers, are refused...
    assert!(matches!(
        unlock_folder_in_place(&folder, b"gravel-tunnel-9", &NoProgress),
        Err(VaultError::WatchOnly)
    ));
    assert_eq!(folder_lock_state(&folder), FolderLockState::Locked, "nothing was restored");
    assert!(!folder.join("film.mp4").exists());

    // ...but the film can be read straight out of the vault.
    let mut v = open_folder_vault(&folder, b"gravel-tunnel-9").unwrap();
    assert!(v.index().watch_only);
    let id = id_of(v.index(), "film.mp4").unwrap();
    assert_eq!(v.read_range(id, 0, 2 * MB).unwrap(), film);
    drop(v);

    // A wrong password learns nothing, watch only or not.
    assert!(matches!(
        open_folder_vault(&folder, b"wrong-password"),
        Err(VaultError::Authentication)
    ));

    // The installed application is the owner's way back in.
    unlock_folder_in_place_with(&folder, b"gravel-tunnel-9", true, &NoProgress).unwrap();
    assert_eq!(fs::read(folder.join("film.mp4")).unwrap(), film);
}

#[test]
fn ordinary_folders_are_unaffected_and_compaction_keeps_the_flag() {
    let fx = Fixture::new();
    let folder = fx.source("Holiday", &[("a.mp4", &pattern(5000, 1))]);
    lock_folder_in_place(&folder, b"gravel-tunnel-9", common::fast_kdf(), false, &NoProgress)
        .unwrap();
    assert!(!open_folder_vault(&folder, b"gravel-tunnel-9").unwrap().index().watch_only);
    unlock_folder_in_place(&folder, b"gravel-tunnel-9", &NoProgress).unwrap();

    let watch = fx.source("Watch", &[("a.mp4", &pattern(5000, 2)), ("b.mp4", b"bbb")]);
    lock_folder_in_place_with(&watch, b"gravel-tunnel-9", common::fast_kdf(), false, true, &NoProgress)
        .unwrap();
    let mut v = OpenVault::unlock(&watch.join(IN_PLACE_VAULT_NAME), b"gravel-tunnel-9").unwrap();
    let b = id_of(v.index(), "b.mp4").unwrap();
    v.delete(b).unwrap();
    let v = v.compact(&NoProgress).unwrap();
    assert!(v.index().watch_only, "rewriting the container must not drop watch only");
}

//! Tampering, corruption and truncation. Nothing here may be silently repaired.

mod common;

use std::fs;
use std::io::Write;

use common::{id_of, Fixture};
use vaultdrive_lib::error::VaultError;
use vaultdrive_lib::vault::format::{DATA_START, HEADER_LEN, SUPERBLOCK_A_OFFSET};
use vaultdrive_lib::vault::{NoProgress, OpenVault};

fn build(fx: &Fixture, payload: &[u8]) {
    let src = fx.source(
        "s",
        &[("a.txt", payload), ("sub/b.bin", &[9u8; 4000]), ("sub/c.txt", b"third")],
    );
    fx.create(&src, "V.vault", "pw").unwrap();
}

fn flip(path: &std::path::Path, offset: usize) {
    let mut bytes = fs::read(path).unwrap();
    bytes[offset] ^= 0x01;
    fs::write(path, bytes).unwrap();
}

#[test]
fn flipping_a_bit_in_the_header_is_detected() {
    let fx = Fixture::new();
    build(&fx, b"payload");
    // Byte 30 sits inside the salt, which is bound as associated data.
    flip(&fx.path("V.vault"), 30);
    let err = fx.unlock("V.vault", "pw").unwrap_err();
    assert!(matches!(err, VaultError::Authentication), "got {err:?}");
}

#[test]
fn flipping_a_bit_in_the_wrapped_key_is_detected() {
    let fx = Fixture::new();
    build(&fx, b"payload");
    flip(&fx.path("V.vault"), HEADER_LEN + 40);
    assert!(matches!(fx.unlock("V.vault", "pw").unwrap_err(), VaultError::Authentication));
}

#[test]
fn flipping_a_bit_in_the_superblock_is_detected_as_corruption_not_a_bad_password() {
    let fx = Fixture::new();
    build(&fx, b"payload");
    // Both slots have to be damaged; a single good slot is a valid vault.
    flip(&fx.path("V.vault"), SUPERBLOCK_A_OFFSET as usize + 30);
    flip(&fx.path("V.vault"), SUPERBLOCK_A_OFFSET as usize + 88 + 30);

    let err = fx.unlock("V.vault", "pw").unwrap_err();
    assert!(matches!(err, VaultError::Integrity), "got {err:?}");
    assert!(err.to_string().contains("integrity check failed"));
}

#[test]
fn flipping_a_bit_in_file_contents_is_detected_when_that_file_is_read() {
    let fx = Fixture::new();
    build(&fx, b"payload that is long enough to be worth corrupting");

    // The data region starts right after the superblocks.
    flip(&fx.path("V.vault"), DATA_START as usize + 5);

    let mut v = fx.unlock("V.vault", "pw").unwrap();
    let mut failures = 0;
    for n in v.index().nodes.iter().filter(|n| !n.is_dir()).map(|n| n.id).collect::<Vec<_>>() {
        if let Err(e) = v.read_file_to_vec(n, usize::MAX) {
            assert!(matches!(e, VaultError::Integrity), "got {e:?}");
            failures += 1;
        }
    }
    assert!(failures >= 1, "corrupting the data region should break at least one file");
}

#[test]
fn a_full_verification_pass_reports_the_corruption() {
    let fx = Fixture::new();
    build(&fx, b"payload that is long enough to be worth corrupting");
    flip(&fx.path("V.vault"), DATA_START as usize + 5);

    let mut v = fx.unlock("V.vault", "pw").unwrap();
    let err = v.verify_all(&NoProgress).unwrap_err();
    assert!(matches!(err, VaultError::Integrity));
}

#[test]
fn an_untampered_vault_passes_a_full_verification_pass() {
    let fx = Fixture::new();
    build(&fx, b"payload");
    let mut v = fx.unlock("V.vault", "pw").unwrap();
    v.verify_all(&NoProgress).unwrap();
}

#[test]
fn a_truncated_vault_fails_safely_at_every_cut_point() {
    let fx = Fixture::new();
    build(&fx, b"payload");
    let full = fs::read(fx.path("V.vault")).unwrap();

    // Cutting at many points, including inside the header, the keywrap, the
    // superblocks, the data region and the index. None may panic, and none may
    // produce a readable vault.
    let mut cuts: Vec<usize> = (0..full.len()).step_by(37).collect();
    cuts.extend([0, 1, 63, 64, 135, 200, 311, full.len() - 1]);
    for cut in cuts {
        let path = fx.path("Truncated.vault");
        fs::write(&path, &full[..cut]).unwrap();
        match OpenVault::unlock(&path, b"pw") {
            Ok(mut v) => {
                // A prefix can still contain a valid header, keywrap and an
                // intact superblock only if the index also survived, which the
                // superblock's own bounds check would have caught. If it opens,
                // reading must still be safe.
                for id in v.index().nodes.iter().map(|n| n.id).collect::<Vec<_>>() {
                    if v.index().get(id).map(|n| n.is_dir()).unwrap_or(true) {
                        continue;
                    }
                    let _ = v.read_file_to_vec(id, usize::MAX);
                }
            }
            Err(e) => {
                assert!(
                    matches!(
                        e,
                        VaultError::NotAVault
                            | VaultError::Truncated
                            | VaultError::Integrity
                            | VaultError::Authentication
                            | VaultError::Io(_)
                    ),
                    "cut at {cut} gave an unexpected error: {e:?}"
                );
            }
        }
        let _ = fs::remove_file(&path);
    }
}

#[test]
fn appending_junk_to_a_vault_does_not_change_what_it_contains() {
    let fx = Fixture::new();
    build(&fx, b"payload");
    let before = {
        let mut v = fx.unlock("V.vault", "pw").unwrap();
        common::dump(&mut v)
    };

    let mut f = fs::OpenOptions::new().append(true).open(fx.path("V.vault")).unwrap();
    f.write_all(&[0xAB; 10_000]).unwrap();
    drop(f);

    let mut v = fx.unlock("V.vault", "pw").unwrap();
    assert_eq!(common::dump(&mut v), before, "trailing junk must be ignored, not trusted");
}

#[test]
fn a_file_that_is_not_a_vault_is_reported_as_such() {
    let fx = Fixture::new();
    let p = fx.path("holiday.jpg");
    fs::write(&p, vec![0x42u8; 5000]).unwrap();
    assert!(matches!(OpenVault::unlock(&p, b"pw").unwrap_err(), VaultError::NotAVault));
}

#[test]
fn an_empty_file_is_reported_as_not_a_vault() {
    let fx = Fixture::new();
    let p = fx.path("empty.vault");
    fs::write(&p, b"").unwrap();
    assert!(matches!(OpenVault::unlock(&p, b"pw").unwrap_err(), VaultError::NotAVault));
}

#[test]
fn a_vault_from_a_future_format_version_is_named_rather_than_guessed_at() {
    let fx = Fixture::new();
    build(&fx, b"payload");
    let mut bytes = fs::read(fx.path("V.vault")).unwrap();
    bytes[8..10].copy_from_slice(&99u16.to_le_bytes());
    fs::write(fx.path("V.vault"), &bytes).unwrap();

    match fx.unlock("V.vault", "pw").unwrap_err() {
        VaultError::VersionMismatch { found, supported } => {
            assert_eq!(found, 99);
            assert_eq!(supported, vaultdrive_lib::vault::FORMAT_VERSION);
        }
        other => panic!("expected VersionMismatch, got {other:?}"),
    }
}

#[test]
fn an_unknown_cipher_id_is_refused_rather_than_ignored() {
    let fx = Fixture::new();
    build(&fx, b"payload");
    let mut bytes = fs::read(fx.path("V.vault")).unwrap();
    bytes[10] = 7;
    fs::write(fx.path("V.vault"), &bytes).unwrap();
    assert!(matches!(fx.unlock("V.vault", "pw").unwrap_err(), VaultError::UnsupportedCipher));
}

#[test]
fn an_absurd_memory_cost_in_the_header_is_refused_before_it_is_allocated() {
    let fx = Fixture::new();
    build(&fx, b"payload");
    let mut bytes = fs::read(fx.path("V.vault")).unwrap();
    // A hostile vault asking for four terabytes of Argon2 memory.
    bytes[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
    fs::write(fx.path("V.vault"), &bytes).unwrap();
    assert!(matches!(
        fx.unlock("V.vault", "pw").unwrap_err(),
        VaultError::UnsupportedKdfParameters
    ));
}

#[test]
fn splicing_a_file_from_one_vault_into_another_does_not_authenticate() {
    let fx = Fixture::new();
    let payload = vec![0x5Au8; 3000];
    let src = fx.source("s", &[("a.bin", &payload)]);
    fx.create(&src, "One.vault", "pw").unwrap();
    fx.create(&src, "Two.vault", "pw").unwrap();

    let one = fs::read(fx.path("One.vault")).unwrap();
    let mut two = fs::read(fx.path("Two.vault")).unwrap();

    // Copy One's entire data region over Two's. Same password, same plaintext,
    // same layout: only the header (bound as associated data) differs.
    let start = DATA_START as usize;
    let len = (two.len() - start).min(one.len() - start);
    two[start..start + len].copy_from_slice(&one[start..start + len]);
    fs::write(fx.path("Two.vault"), &two).unwrap();

    let err = fx.unlock("Two.vault", "pw").unwrap_err();
    assert!(
        matches!(err, VaultError::Integrity | VaultError::Truncated),
        "cross-vault splice should not authenticate, got {err:?}"
    );
}

#[test]
fn zeroing_both_superblocks_is_reported_as_corruption() {
    let fx = Fixture::new();
    build(&fx, b"payload");
    let mut bytes = fs::read(fx.path("V.vault")).unwrap();
    for b in bytes.iter_mut().skip(SUPERBLOCK_A_OFFSET as usize).take(176) {
        *b = 0;
    }
    fs::write(fx.path("V.vault"), &bytes).unwrap();
    assert!(matches!(fx.unlock("V.vault", "pw").unwrap_err(), VaultError::Integrity));
}

#[test]
fn a_corrupted_vault_is_never_silently_repaired() {
    let fx = Fixture::new();
    build(&fx, b"payload worth protecting");
    let original = fs::read(fx.path("V.vault")).unwrap();

    flip(&fx.path("V.vault"), DATA_START as usize + 3);
    let mut v = fx.unlock("V.vault", "pw").unwrap();
    let id = id_of(v.index(), "a.txt").unwrap();
    let _ = v.read_file_to_vec(id, usize::MAX);
    drop(v);

    let after = fs::read(fx.path("V.vault")).unwrap();
    let differing: Vec<usize> =
        (0..original.len().min(after.len())).filter(|i| original[*i] != after[*i]).collect();
    assert_eq!(
        differing,
        vec![DATA_START as usize + 3],
        "reading a damaged vault must not rewrite it"
    );
}

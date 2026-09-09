//! Password handling: what unlocks a vault and what does not.

mod common;

use common::Fixture;
use vaultdrive_lib::error::VaultError;

#[test]
fn the_correct_password_unlocks_the_vault() {
    let fx = Fixture::new();
    let src = fx.source("secret", &[("notes.txt", b"hello")]);
    fx.create(&src, "MyVault.vault", "correct horse battery staple").unwrap();

    let vault = fx.unlock("MyVault.vault", "correct horse battery staple").unwrap();
    assert_eq!(vault.index().stats().0, 1);
}

#[test]
fn an_incorrect_password_fails() {
    let fx = Fixture::new();
    let src = fx.source("secret", &[("notes.txt", b"hello")]);
    fx.create(&src, "MyVault.vault", "the right one").unwrap();

    let err = fx.unlock("MyVault.vault", "the wrong one").unwrap_err();
    assert!(matches!(err, VaultError::Authentication));
}

#[test]
fn a_nearly_correct_password_fails_the_same_way_as_a_wildly_wrong_one() {
    let fx = Fixture::new();
    let src = fx.source("secret", &[("a.txt", b"x")]);
    fx.create(&src, "V.vault", "SuperSecret123").unwrap();

    let near = fx.unlock("V.vault", "SuperSecret124").unwrap_err();
    let far = fx.unlock("V.vault", "z").unwrap_err();

    // Same variant, same text. Nothing about the message narrows the search.
    assert_eq!(near.kind(), far.kind());
    assert_eq!(near.to_string(), far.to_string());
    assert_eq!(near.to_string(), "Incorrect password.\nThe vault could not be unlocked.");
}

#[test]
fn an_empty_password_is_refused_at_creation_rather_than_silently_accepted() {
    let fx = Fixture::new();
    let src = fx.source("secret", &[("a.txt", b"x")]);
    let err = fx.create(&src, "Empty.vault", "").unwrap_err();
    assert!(matches!(err, VaultError::InvalidInput(_)));
    assert!(!fx.path("Empty.vault").exists(), "no vault should have been written");
}

#[test]
fn an_empty_password_does_not_open_a_real_vault() {
    let fx = Fixture::new();
    let src = fx.source("secret", &[("a.txt", b"x")]);
    fx.create(&src, "V.vault", "a real password").unwrap();
    assert!(matches!(fx.unlock("V.vault", "").unwrap_err(), VaultError::Authentication));
}

#[test]
fn a_very_long_password_works() {
    let fx = Fixture::new();
    let long: String = "a-long-passphrase-segment-".repeat(200); // ~5 KB
    let src = fx.source("secret", &[("a.txt", b"payload")]);
    fx.create(&src, "Long.vault", &long).unwrap();

    let mut v = fx.unlock("Long.vault", &long).unwrap();
    let id = common::id_of(v.index(), "a.txt").unwrap();
    assert_eq!(v.read_file_to_vec(id, usize::MAX).unwrap(), b"payload");

    assert!(fx.unlock("Long.vault", &long[..long.len() - 1]).is_err());
}

#[test]
fn passwords_with_unicode_and_spaces_work() {
    let fx = Fixture::new();
    let pw = "гора 🏔 ist schön — ¡sí!";
    let src = fx.source("secret", &[("a.txt", b"x")]);
    fx.create(&src, "U.vault", pw).unwrap();
    assert!(fx.unlock("U.vault", pw).is_ok());
    assert!(fx.unlock("U.vault", "гора 🏔 ist schon — ¡sí!").is_err());
}

#[test]
fn two_vaults_with_the_same_password_use_different_salts_and_different_ciphertext() {
    let fx = Fixture::new();
    let src = fx.source("secret", &[("a.txt", b"identical contents")]);
    fx.create(&src, "One.vault", "same password").unwrap();
    fx.create(&src, "Two.vault", "same password").unwrap();

    let a = common::raw(&fx.path("One.vault"));
    let b = common::raw(&fx.path("Two.vault"));

    // Salt lives at offset 24..56 of the header.
    assert_ne!(&a[24..56], &b[24..56], "every vault must get a fresh salt");
    assert_ne!(a, b, "identical input under one password must not give identical files");
}

#[test]
fn the_password_for_one_vault_does_not_open_another() {
    let fx = Fixture::new();
    let src = fx.source("secret", &[("a.txt", b"x")]);
    fx.create(&src, "A.vault", "password A").unwrap();
    fx.create(&src, "B.vault", "password B").unwrap();

    assert!(fx.unlock("A.vault", "password B").is_err());
    assert!(fx.unlock("B.vault", "password A").is_err());
}

#[test]
fn password_strength_scoring_is_length_led_not_symbol_led() {
    use vaultdrive_lib::password::estimate;
    assert_eq!(estimate("Password1!").score, 0);
    assert!(estimate("gravel tunnel morning kettle").score >= 2);
}
